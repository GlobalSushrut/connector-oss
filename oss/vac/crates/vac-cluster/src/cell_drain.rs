//! I17 — Graceful cell draining for zero-downtime rolling deployments.
//!
//! `CellDrain::begin(cell_id)` orchestrates a safe drain sequence:
//!   1. Pause new assignments to the draining cell.
//!   2. Migrate all live agents to successor cells via ConsistentHashRing.
//!   3. Confirm zero local agents remain.
//!   4. Remove the cell from the ring.
//!
//! This enables rolling restarts without dropping in-flight work.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::ring::ConsistentHashRing;

// ── Drain Errors ─────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum DrainError {
    #[error("Cell not found in ring: {0}")]
    CellNotFound(String),

    #[error("No successor available for agent {agent_pid} (ring has only one cell)")]
    NoSuccessor { agent_pid: String },

    #[error("Drain failed: {0} agents could not be migrated")]
    MigrationFailed(usize),

    #[error("Internal drain error: {0}")]
    Internal(String),
}

pub type DrainResult<T> = Result<T, DrainError>;

// ── Agent Migration Record ────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AgentMigration {
    pub agent_pid: String,
    pub from_cell: String,
    pub to_cell: String,
}

// ── Drain Stats ───────────────────────────────────────────────────────

#[derive(Debug, Default, Clone)]
pub struct DrainStats {
    pub cell_id: String,
    pub agents_migrated: usize,
    pub agents_failed: usize,
    pub migrations: Vec<AgentMigration>,
}

// ── Agent Registry Trait ──────────────────────────────────────────────

/// Abstraction over the agent registry so `CellDrain` can be tested
/// without a live kernel.
pub trait AgentRegistry: Send + Sync {
    /// Return the PIDs of all agents currently assigned to `cell_id`.
    fn agents_on_cell(&self, cell_id: &str) -> Vec<String>;

    /// Reassign `agent_pid` from `from_cell` to `to_cell`.
    /// Returns `Ok(())` on success or an error string on failure.
    fn reassign(&mut self, agent_pid: &str, from_cell: &str, to_cell: &str) -> Result<(), String>;
}

// ── CellDrain ─────────────────────────────────────────────────────────

pub struct CellDrain {
    ring: Arc<Mutex<ConsistentHashRing>>,
    paused: Mutex<std::collections::HashSet<String>>,
}

impl CellDrain {
    pub fn new(ring: Arc<Mutex<ConsistentHashRing>>) -> Self {
        Self {
            ring,
            paused: Mutex::new(std::collections::HashSet::new()),
        }
    }

    /// Returns `true` if `cell_id` is currently paused for new assignments.
    pub fn is_paused(&self, cell_id: &str) -> bool {
        self.paused.lock().unwrap().contains(cell_id)
    }

    /// Full drain sequence (synchronous for deterministic testing).
    ///
    /// Steps:
    ///   1. Verify cell is in ring.
    ///   2. Mark cell as paused (no new assignments).
    ///   3. For each live agent on the cell, route to successor via ring.
    ///   4. Call `registry.reassign(...)` for each agent.
    ///   5. Verify zero agents remain.
    ///   6. Remove cell from ring and unpause.
    pub fn begin<R: AgentRegistry>(
        &self,
        cell_id: &str,
        registry: &mut R,
    ) -> DrainResult<DrainStats> {
        // Step 1: verify membership
        {
            let ring = self.ring.lock().unwrap();
            if !ring.contains(cell_id) {
                return Err(DrainError::CellNotFound(cell_id.to_string()));
            }
        }

        // Step 2: pause new assignments
        self.paused.lock().unwrap().insert(cell_id.to_string());

        let mut stats = DrainStats {
            cell_id: cell_id.to_string(),
            ..Default::default()
        };

        // Step 3+4: migrate each live agent to its ring successor
        let agents = registry.agents_on_cell(cell_id);
        for agent_pid in &agents {
            let successor = {
                let ring = self.ring.lock().unwrap();
                // Find the first successor cell that is not the draining cell itself.
                // get_successor skips the primary but may return the draining cell
                // when the ring has overlapping virtual-node positions.
                let mut candidate = ring.get_successor(agent_pid)
                    .map(|s| s.to_string());
                // If the ring returned the draining cell as successor, try cells list
                if candidate.as_deref() == Some(cell_id) {
                    candidate = ring.cells()
                        .iter()
                        .find(|c| c.as_str() != cell_id)
                        .cloned();
                }
                candidate.ok_or_else(|| DrainError::NoSuccessor { agent_pid: agent_pid.clone() })?
            };
            match registry.reassign(agent_pid, cell_id, &successor) {
                Ok(()) => {
                    stats.migrations.push(AgentMigration {
                        agent_pid: agent_pid.clone(),
                        from_cell: cell_id.to_string(),
                        to_cell: successor,
                    });
                    stats.agents_migrated += 1;
                }
                Err(_) => {
                    stats.agents_failed += 1;
                }
            }
        }

        // Step 5: confirm zero agents remain
        let remaining = registry.agents_on_cell(cell_id).len();
        if remaining > 0 {
            // Unpause before returning error to allow retry
            self.paused.lock().unwrap().remove(cell_id);
            return Err(DrainError::MigrationFailed(remaining));
        }

        // Step 6: remove from ring and unpause
        {
            let mut ring = self.ring.lock().unwrap();
            ring.remove_cell(cell_id);
        }
        self.paused.lock().unwrap().remove(cell_id);

        Ok(stats)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    struct MockRegistry {
        assignments: HashMap<String, String>,
    }

    impl MockRegistry {
        fn new() -> Self {
            Self { assignments: HashMap::new() }
        }

        fn assign(&mut self, agent_pid: &str, cell_id: &str) {
            self.assignments.insert(agent_pid.to_string(), cell_id.to_string());
        }
    }

    impl AgentRegistry for MockRegistry {
        fn agents_on_cell(&self, cell_id: &str) -> Vec<String> {
            self.assignments
                .iter()
                .filter(|(_, c)| c.as_str() == cell_id)
                .map(|(pid, _)| pid.clone())
                .collect()
        }

        fn reassign(&mut self, agent_pid: &str, _from: &str, to_cell: &str) -> Result<(), String> {
            self.assignments.insert(agent_pid.to_string(), to_cell.to_string());
            Ok(())
        }
    }

    fn make_ring(cells: &[&str]) -> Arc<Mutex<ConsistentHashRing>> {
        let mut ring = ConsistentHashRing::new();
        for c in cells { ring.add_cell(*c); }
        Arc::new(Mutex::new(ring))
    }

    #[test]
    fn test_drain_migrates_all_agents_to_successors() {
        let ring = make_ring(&["cell-1", "cell-2", "cell-3"]);
        let drain = CellDrain::new(Arc::clone(&ring));

        let mut registry = MockRegistry::new();
        for i in 0..10 {
            registry.assign(&format!("agent-{}", i), "cell-1");
        }

        let stats = drain.begin("cell-1", &mut registry).unwrap();

        assert_eq!(stats.agents_migrated, 10);
        assert_eq!(stats.agents_failed, 0);
        // All agents must now be on a non-cell-1 cell
        for i in 0..10 {
            let assigned = registry.assignments.get(&format!("agent-{}", i)).unwrap();
            assert_ne!(assigned, "cell-1", "agent-{} still on drained cell", i);
        }
    }

    #[test]
    fn test_drain_removes_cell_from_ring() {
        let ring = make_ring(&["cell-1", "cell-2"]);
        let drain = CellDrain::new(Arc::clone(&ring));
        let mut registry = MockRegistry::new();
        registry.assign("agent-0", "cell-1");

        drain.begin("cell-1", &mut registry).unwrap();

        let ring_guard = ring.lock().unwrap();
        assert!(!ring_guard.contains("cell-1"), "Drained cell must be removed from ring");
    }

    #[test]
    fn test_drain_pauses_during_migration() {
        let ring = make_ring(&["cell-1", "cell-2"]);
        let drain = CellDrain::new(Arc::clone(&ring));
        // Before drain: not paused
        assert!(!drain.is_paused("cell-1"));
        // After drain: not paused (cleaned up)
        let mut registry = MockRegistry::new();
        drain.begin("cell-1", &mut registry).unwrap();
        assert!(!drain.is_paused("cell-1"));
    }

    #[test]
    fn test_drain_returns_error_for_unknown_cell() {
        let ring = make_ring(&["cell-1"]);
        let drain = CellDrain::new(Arc::clone(&ring));
        let mut registry = MockRegistry::new();
        let result = drain.begin("cell-99", &mut registry);
        assert!(matches!(result, Err(DrainError::CellNotFound(_))));
    }

    #[test]
    fn test_drain_error_when_only_one_cell_and_agents_present() {
        let ring = make_ring(&["cell-1"]);
        let drain = CellDrain::new(Arc::clone(&ring));
        let mut registry = MockRegistry::new();
        registry.assign("agent-0", "cell-1");

        let result = drain.begin("cell-1", &mut registry);
        assert!(
            matches!(result, Err(DrainError::NoSuccessor { .. }) | Err(DrainError::MigrationFailed(_))),
            "Should fail when no successor exists"
        );
    }

    #[test]
    fn test_drain_empty_cell_succeeds_immediately() {
        let ring = make_ring(&["cell-1", "cell-2"]);
        let drain = CellDrain::new(Arc::clone(&ring));
        let mut registry = MockRegistry::new();

        let stats = drain.begin("cell-1", &mut registry).unwrap();
        assert_eq!(stats.agents_migrated, 0);
    }
}
