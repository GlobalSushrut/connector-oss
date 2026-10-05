//! Per-agent authority epoch — sinks must verify at redeem (Phase C).

use std::sync::Arc;

use dashmap::DashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct AuthorityEpoch(pub u64);

impl AuthorityEpoch {
    pub fn get(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Default, Clone)]
pub struct AuthorityEpochStore {
    inner: Arc<DashMap<String, u64>>,
}

impl AuthorityEpochStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn current(&self, agent_id: &str) -> AuthorityEpoch {
        AuthorityEpoch(*self.inner.entry(agent_id.to_string()).or_insert(0))
    }

    /// Bump on grant change, charter demote, quarantine, operator revoke.
    pub fn bump(&self, agent_id: &str) -> AuthorityEpoch {
        let mut e = self.inner.entry(agent_id.to_string()).or_insert(0);
        *e = e.saturating_add(1);
        AuthorityEpoch(*e)
    }

    pub fn set_for_test(&self, agent_id: &str, epoch: u64) {
        self.inner.insert(agent_id.to_string(), epoch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bump_advances() {
        let s = AuthorityEpochStore::new();
        assert_eq!(s.current("a").get(), 0);
        assert_eq!(s.bump("a").get(), 1);
        assert_eq!(s.bump("a").get(), 2);
        assert_eq!(s.current("a").get(), 2);
    }

    #[test]
    fn stale_epoch_detectable() {
        let s = AuthorityEpochStore::new();
        let lease_epoch = s.current("a").get();
        s.bump("a"); // quarantine
        assert_ne!(lease_epoch, s.current("a").get());
    }
}
