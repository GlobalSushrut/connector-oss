//! In-process AgencyTransaction store (B0 durable via COPG/jsonl).

use std::sync::Arc;

use dashmap::DashMap;

use super::transaction::{AgencyTransaction, TransitionError, TxState};

#[derive(Debug, Default, Clone)]
pub struct TransactionStore {
    inner: Arc<DashMap<String, AgencyTransaction>>,
}

impl TransactionStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, tx: AgencyTransaction) -> String {
        let id = tx.tx_id.clone();
        crate::substrate::arc::durable::persist_agency_tx(&tx);
        self.inner.insert(id.clone(), tx);
        id
    }

    /// Boot hydrate — memory only (already durable).
    pub fn hydrate_memory_only(&self, tx: AgencyTransaction) {
        self.inner.insert(tx.tx_id.clone(), tx);
    }

    pub fn list_all(&self) -> Vec<AgencyTransaction> {
        self.inner.iter().map(|e| e.clone()).collect()
    }

    pub fn get(&self, tx_id: &str) -> Option<AgencyTransaction> {
        self.inner.get(tx_id).map(|e| e.clone())
    }

    pub fn transition(&self, tx_id: &str, to: TxState) -> Result<AgencyTransaction, String> {
        let mut entry = self
            .inner
            .get_mut(tx_id)
            .ok_or_else(|| format!("unknown tx {tx_id}"))?;
        entry
            .transition(to)
            .map_err(|e: TransitionError| e.to_string())?;
        let cloned = entry.clone();
        crate::substrate::arc::durable::persist_agency_tx(&cloned);
        Ok(cloned)
    }

    /// After process kill while EFFECT_STARTED: mark EFFECT_UNKNOWN (no COMMITTED).
    pub fn recover_crash_effect_started(&self, tx_id: &str) -> Result<AgencyTransaction, String> {
        let mut entry = self
            .inner
            .get_mut(tx_id)
            .ok_or_else(|| format!("unknown tx {tx_id}"))?;
        if entry.state != TxState::EffectStarted {
            return Err(format!(
                "recover only from EFFECT_STARTED, got {}",
                entry.state.as_str()
            ));
        }
        entry
            .mark_effect_unknown_after_crash()
            .map_err(|e| e.to_string())?;
        let cloned = entry.clone();
        crate::substrate::arc::durable::persist_agency_tx(&cloned);
        Ok(cloned)
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn list_for_agent(&self, agent_id: &str) -> Vec<AgencyTransaction> {
        self.inner
            .iter()
            .filter(|e| e.agent_id == agent_id)
            .map(|e| e.clone())
            .collect()
    }

    /// RESERVED tx for this admit (idempotency_key = PATE task_id).
    pub fn find_reserved_for_agent(
        &self,
        agent_id: &str,
        idempotency_key: &str,
    ) -> Option<AgencyTransaction> {
        self.inner.iter().find_map(|e| {
            if e.agent_id == agent_id
                && e.state == TxState::Reserved
                && e.idempotency_key.as_deref() == Some(idempotency_key)
            {
                Some(e.clone())
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::substrate::arc::transaction::AgencyTransaction;

    #[test]
    fn crash_recovery_to_effect_unknown() {
        let store = TransactionStore::new();
        let mut tx = AgencyTransaction::new("a1", 0, None);
        for s in [
            TxState::Validated,
            TxState::Reserved,
            TxState::Leased,
            TxState::Redeeming,
            TxState::EffectStarted,
        ] {
            tx.transition(s).unwrap();
        }
        let id = store.insert(tx);
        let recovered = store.recover_crash_effect_started(&id).unwrap();
        assert_eq!(recovered.state, TxState::EffectUnknown);
        assert!(store.transition(&id, TxState::Committed).is_err());
    }
}
