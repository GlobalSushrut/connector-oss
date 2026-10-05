//! In-process WorldlineCommit store (Phase E; COPG/redb durable when enabled).

use std::sync::Arc;

use dashmap::DashMap;

use super::worldline::WorldlineCommit;

#[derive(Debug, Default, Clone)]
pub struct WorldlineStore {
    /// agent_id → ordered commits
    by_agent: Arc<DashMap<String, Vec<WorldlineCommit>>>,
}

impl WorldlineStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&self, commit: WorldlineCommit) {
        crate::substrate::arc::durable::persist_worldline_commit(&commit);
        self.append_memory_only(commit);
    }

    /// In-memory only (used by durable loader to avoid re-write).
    pub fn append_memory_only(&self, commit: WorldlineCommit) {
        self.by_agent
            .entry(commit.agent_id.clone())
            .or_default()
            .push(commit);
    }

    pub fn head(&self, agent_id: &str) -> Option<WorldlineCommit> {
        self.by_agent
            .get(agent_id)
            .and_then(|v| v.last().cloned())
    }

    pub fn list(&self, agent_id: &str) -> Vec<WorldlineCommit> {
        self.by_agent
            .get(agent_id)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.by_agent.iter().map(|e| e.value().len()).sum()
    }
}
