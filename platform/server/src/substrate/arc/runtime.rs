//! Process-local ARC runtime stores (Phase B/C/E). Durable via COPG/jsonl.

use std::sync::OnceLock;

use super::authority_epoch::{AuthorityEpoch, AuthorityEpochStore};
use super::lease_store::LeaseStore;
use super::transaction_store::TransactionStore;
use super::worldline_store::WorldlineStore;

static EPOCHS: OnceLock<AuthorityEpochStore> = OnceLock::new();
static TXS: OnceLock<TransactionStore> = OnceLock::new();
static LEASES: OnceLock<LeaseStore> = OnceLock::new();
static WORLD: OnceLock<WorldlineStore> = OnceLock::new();

pub fn epochs() -> &'static AuthorityEpochStore {
    EPOCHS.get_or_init(AuthorityEpochStore::new)
}

pub fn transactions() -> &'static TransactionStore {
    TXS.get_or_init(TransactionStore::new)
}

pub fn leases() -> &'static LeaseStore {
    LEASES.get_or_init(LeaseStore::new)
}

pub fn worldline() -> &'static WorldlineStore {
    WORLD.get_or_init(|| {
        let s = WorldlineStore::new();
        crate::substrate::arc::durable::load_worldline_into(&s);
        s
    })
}

/// Sink-readable authority epoch for an agent (B1).
pub fn authority_epoch(agent_id: &str) -> AuthorityEpoch {
    epochs().current(agent_id)
}
