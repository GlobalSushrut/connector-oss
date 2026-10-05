//! In-process ConsequenceLease store (Phase C; sqlite later with Phase E).

use std::sync::Arc;

use dashmap::DashMap;

use super::lease::ConsequenceLease;

#[derive(Debug, Default, Clone)]
pub struct LeaseStore {
    by_id: Arc<DashMap<String, ConsequenceLease>>,
    by_tx: Arc<DashMap<String, String>>,
}

impl LeaseStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, lease: ConsequenceLease) {
        crate::substrate::arc::durable::persist_lease(&lease);
        self.by_tx
            .insert(lease.tx_id.clone(), lease.lease_id.clone());
        self.by_id.insert(lease.lease_id.clone(), lease);
    }

    /// Boot hydrate — already durable on disk (skip re-persist).
    pub fn hydrate_memory_only(&self, lease: ConsequenceLease) {
        self.by_tx
            .insert(lease.tx_id.clone(), lease.lease_id.clone());
        self.by_id.insert(lease.lease_id.clone(), lease);
    }

    pub fn get(&self, lease_id: &str) -> Option<ConsequenceLease> {
        self.by_id.get(lease_id).map(|e| e.clone())
    }

    pub fn by_tx(&self, tx_id: &str) -> Option<ConsequenceLease> {
        let lid = self.by_tx.get(tx_id)?;
        self.get(lid.value())
    }

    pub fn revoke_agent(&self, agent_id: &str) -> usize {
        let mut n = 0usize;
        for mut e in self.by_id.iter_mut() {
            if e.agent_id == agent_id && !e.revoked {
                e.revoked = true;
                n += 1;
            }
        }
        n
    }

    /// Live (redeemable) leases for agent (G6).
    pub fn open_for_agent(&self, agent_id: &str) -> Vec<ConsequenceLease> {
        self.by_id
            .iter()
            .filter(|e| e.agent_id == agent_id && !e.revoked && !e.redeemed)
            .map(|e| e.clone())
            .collect()
    }

    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}
