//! # Thought Checkpoint & Recovery
//!
//! Saves cognitive state at each layer transition so that if a cycle fails
//! mid-way, recovery starts from the last checkpoint. No cognitive state
//! is silently lost.

use super::types::*;
use std::collections::HashMap;

/// Manages thought checkpoints for recovery across cognitive cycles.
pub struct CheckpointManager {
    /// agent_pid → vec of checkpoints (newest last)
    checkpoints: HashMap<String, Vec<ThoughtCheckpoint>>,
    /// Maximum checkpoints to retain per agent
    max_per_agent: usize,
}

impl CheckpointManager {
    pub fn new(max_per_agent: usize) -> Self {
        Self {
            checkpoints: HashMap::new(),
            max_per_agent,
        }
    }

    /// Save a checkpoint at the current layer.
    pub fn save(
        &mut self,
        agent_pid: &str,
        cycle_number: u32,
        layer: u8,
        state: ThoughtCheckpointState,
    ) -> String {
        let now = chrono::Utc::now().timestamp();
        let checkpoint_id = format!("ckpt:{}:{}:L{}", agent_pid, cycle_number, layer);

        let checkpoint = ThoughtCheckpoint {
            checkpoint_id: checkpoint_id.clone(),
            agent_pid: agent_pid.to_string(),
            cycle_number,
            layer,
            timestamp: now,
            state,
            cid: None, // CID computed by VAC on storage
        };

        let agent_checkpoints = self.checkpoints.entry(agent_pid.to_string()).or_default();
        agent_checkpoints.push(checkpoint);

        // Enforce retention limit
        if agent_checkpoints.len() > self.max_per_agent {
            let excess = agent_checkpoints.len() - self.max_per_agent;
            agent_checkpoints.drain(..excess);
        }

        checkpoint_id
    }

    /// Recover the latest checkpoint for an agent.
    pub fn recover(&self, agent_pid: &str) -> Option<&ThoughtCheckpoint> {
        self.checkpoints
            .get(agent_pid)
            .and_then(|cps| cps.last())
    }

    /// Recover the latest checkpoint at or before a specific layer.
    pub fn recover_at_layer(&self, agent_pid: &str, max_layer: u8) -> Option<&ThoughtCheckpoint> {
        self.checkpoints
            .get(agent_pid)
            .and_then(|cps| {
                cps.iter()
                    .rev()
                    .find(|cp| cp.layer <= max_layer)
            })
    }

    /// List all checkpoints for an agent.
    pub fn list(&self, agent_pid: &str) -> Vec<&ThoughtCheckpoint> {
        self.checkpoints
            .get(agent_pid)
            .map(|cps| cps.iter().collect())
            .unwrap_or_default()
    }

    /// Purge old checkpoints, keeping only the last `keep` entries.
    pub fn purge(&mut self, agent_pid: &str, keep: usize) {
        if let Some(cps) = self.checkpoints.get_mut(agent_pid) {
            if cps.len() > keep {
                let excess = cps.len() - keep;
                cps.drain(..excess);
            }
        }
    }

    /// Clear all checkpoints for an agent (e.g., after successful cycle completion).
    pub fn clear(&mut self, agent_pid: &str) {
        self.checkpoints.remove(agent_pid);
    }

    /// Total checkpoint count across all agents.
    pub fn total_count(&self) -> usize {
        self.checkpoints.values().map(|v| v.len()).sum()
    }
}

impl Default for CheckpointManager {
    fn default() -> Self {
        Self::new(20)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state(layer: u8) -> ThoughtCheckpointState {
        ThoughtCheckpointState {
            meanings: vec![MeaningObject {
                id: format!("m:{}", layer),
                source_perception: "perc:1".into(),
                meaning_type: MeaningType::Information { topic: "test".into() },
                entities: vec![],
                salience: 0.5,
                confidence: 0.8,
                evidence_cids: vec![],
            }],
            tensions: TensionGraph::default(),
            active_knowledge: None,
            possibilities: vec![],
            evaluations: vec![],
            commitments: CommitmentRegister::default(),
            plan: None,
        }
    }

    #[test]
    fn test_save_and_recover() {
        let mut mgr = CheckpointManager::new(10);
        mgr.save("pid:bot", 1, 2, make_state(2));
        mgr.save("pid:bot", 1, 5, make_state(5));

        let latest = mgr.recover("pid:bot");
        assert!(latest.is_some());
        assert_eq!(latest.unwrap().layer, 5);
    }

    #[test]
    fn test_recover_at_layer() {
        let mut mgr = CheckpointManager::new(10);
        mgr.save("pid:bot", 1, 2, make_state(2));
        mgr.save("pid:bot", 1, 5, make_state(5));
        mgr.save("pid:bot", 1, 8, make_state(8));

        let at_5 = mgr.recover_at_layer("pid:bot", 5);
        assert!(at_5.is_some());
        assert_eq!(at_5.unwrap().layer, 5);
    }

    #[test]
    fn test_retention_limit() {
        let mut mgr = CheckpointManager::new(3);
        for i in 0..5 {
            mgr.save("pid:bot", 1, i, make_state(i));
        }
        assert_eq!(mgr.list("pid:bot").len(), 3);
    }

    #[test]
    fn test_purge() {
        let mut mgr = CheckpointManager::new(10);
        for i in 0..5 {
            mgr.save("pid:bot", 1, i, make_state(i));
        }
        mgr.purge("pid:bot", 2);
        assert_eq!(mgr.list("pid:bot").len(), 2);
    }

    #[test]
    fn test_clear() {
        let mut mgr = CheckpointManager::new(10);
        mgr.save("pid:bot", 1, 0, make_state(0));
        mgr.clear("pid:bot");
        assert!(mgr.recover("pid:bot").is_none());
    }
}
