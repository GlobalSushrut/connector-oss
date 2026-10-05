//! Intelligence Access Cell (IAC) — per-agent concurrency and consistency unit.
//!
//! Each `agent_pid` owns an epoch (mac-consistency L1), inflight budget, and
//! optional read-set stamp (L2). Talk/RAG/tools acquire the cell rather than a
//! global process lock for agent-scoped control.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use tokio::sync::Notify;

/// Default concurrent generations / effects per intelligence (env override).
pub fn inflight_cap() -> usize {
    std::env::var("CONNECTOR_I_INFLIGHT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4)
        .max(1)
}

#[derive(Debug, Default, Clone)]
pub struct ReadSet {
    /// Schema marker for L2 stamping (connector.read_set.v1).
    pub schema: String,
    pub wm_cids: Vec<String>,
    pub vac_namespaces: Vec<String>,
    /// VAC packet CIDs observed during the run (evidence stamps).
    pub vac_cids: Vec<String>,
    pub stamped_epoch: u64,
    pub broker_epoch: u64,
}

impl ReadSet {
    pub fn fresh_schema() -> Self {
        Self {
            schema: "connector.read_set.v1".into(),
            ..Default::default()
        }
    }
}

/// Per-intelligence isolation cell.
pub struct IntelligenceCell {
    pub agent_pid: String,
    pub epoch: AtomicU64,
    pub inflight: AtomicUsize,
    pub inflight_notify: Notify,
    pub disorder_radius_fp: AtomicU64,
    pub read_set: RwLock<ReadSet>,
    pub last_touch: Mutex<Instant>,
}

impl IntelligenceCell {
    pub fn new(agent_pid: impl Into<String>) -> Self {
        Self {
            agent_pid: agent_pid.into(),
            epoch: AtomicU64::new(1),
            inflight: AtomicUsize::new(0),
            inflight_notify: Notify::new(),
            disorder_radius_fp: AtomicU64::new(0),
            read_set: RwLock::new(ReadSet::default()),
            last_touch: Mutex::new(Instant::now()),
        }
    }

    pub fn current_epoch(&self) -> u64 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Bump epoch (quarantine / revoke / charter change). Stale ATUs see mismatch.
    pub fn bump_epoch(&self) -> u64 {
        let next = self.epoch.fetch_add(1, Ordering::SeqCst) + 1;
        if let Ok(mut rs) = self.read_set.write() {
            rs.wm_cids.clear();
            rs.vac_namespaces.clear();
            rs.vac_cids.clear();
            rs.broker_epoch = 0;
            // Force re-stamp after bump — 0 means "no valid read-set for this epoch".
            rs.stamped_epoch = 0;
        }
        self.touch();
        next
    }

    pub fn touch(&self) {
        if let Ok(mut t) = self.last_touch.lock() {
            *t = Instant::now();
        }
    }

    /// Try to reserve one inflight slot. Err if at cap.
    pub fn try_acquire_inflight(&self) -> Result<(), String> {
        let cap = inflight_cap();
        loop {
            let cur = self.inflight.load(Ordering::SeqCst);
            if cur >= cap {
                return Err(format!(
                    "inflight_cap: agent={} has {cap} concurrent slots",
                    self.agent_pid
                ));
            }
            if self
                .inflight
                .compare_exchange(cur, cur + 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                self.touch();
                return Ok(());
            }
        }
    }

    pub fn release_inflight(&self) {
        let _ = self.inflight.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |v| {
            Some(v.saturating_sub(1))
        });
        self.inflight_notify.notify_waiters();
        self.touch();
    }

    pub fn stamp_read_set(&self, wm_cids: Vec<String>, vac_namespaces: Vec<String>) {
        self.stamp_read_set_full(wm_cids, vac_namespaces, Vec::new(), 0);
    }

    /// L2 stamp with VAC evidence CIDs + broker generation.
    pub fn stamp_read_set_full(
        &self,
        wm_cids: Vec<String>,
        vac_namespaces: Vec<String>,
        vac_cids: Vec<String>,
        broker_epoch: u64,
    ) {
        let epoch = self.current_epoch();
        if let Ok(mut rs) = self.read_set.write() {
            if rs.schema.is_empty() {
                rs.schema = "connector.read_set.v1".into();
            }
            rs.wm_cids = wm_cids;
            rs.vac_namespaces = vac_namespaces;
            rs.vac_cids = vac_cids;
            rs.broker_epoch = broker_epoch;
            rs.stamped_epoch = epoch;
        }
        self.touch();
    }

    /// L2: Err when stamped read-set is stale vs live epoch (409 DeferRedo).
    pub fn assert_read_set_fresh_or_stale(&self) -> Result<(), String> {
        if self.read_set_fresh() {
            Ok(())
        } else {
            Err(format!(
                "read_set_stale: agent={} live_epoch={}",
                self.agent_pid,
                self.current_epoch()
            ))
        }
    }

    /// L2: true when a read-set was stamped for the live cell epoch.
    pub fn read_set_fresh(&self) -> bool {
        let epoch = self.current_epoch();
        self.read_set
            .read()
            .map(|rs| rs.stamped_epoch != 0 && rs.stamped_epoch == epoch)
            .unwrap_or(false)
    }
}

/// RAII guard that releases inflight on drop.
pub struct InflightGuard {
    cell: Arc<IntelligenceCell>,
}

impl InflightGuard {
    pub fn try_acquire(cell: Arc<IntelligenceCell>) -> Result<Self, String> {
        cell.try_acquire_inflight()?;
        Ok(Self { cell })
    }
}

impl Drop for InflightGuard {
    fn drop(&mut self) {
        self.cell.release_inflight();
    }
}

/// Global registry of IntelligenceCells keyed by agent_pid.
pub struct CellRegistry {
    inner: RwLock<HashMap<String, Arc<IntelligenceCell>>>,
}

impl Default for CellRegistry {
    fn default() -> Self {
        Self {
            inner: RwLock::new(HashMap::new()),
        }
    }
}

impl CellRegistry {
    pub fn get_or_create(&self, agent_pid: &str) -> Arc<IntelligenceCell> {
        let key = agent_pid.trim();
        if let Ok(map) = self.inner.read() {
            if let Some(c) = map.get(key) {
                return Arc::clone(c);
            }
        }
        let mut map = self.inner.write().expect("cell_registry_write");
        map.entry(key.to_string())
            .or_insert_with(|| Arc::new(IntelligenceCell::new(key)))
            .clone()
    }

    pub fn bump_epoch(&self, agent_pid: &str) -> u64 {
        // ARC authority epoch must advance with IAC epoch (grant/quarantine/revoke).
        let _ = crate::substrate::arc::runtime::epochs().bump(agent_pid);
        // C5: revoke open ConsequenceLeases — sinks fail redeem (NoLease⇒NoEffect).
        let _ = crate::substrate::arc::lease::revoke_agent_leases(agent_pid);
        // G6: quarantine reachability proof (log QUARANTINE_FAILED if mid-flight remains).
        let proof = crate::substrate::arc::quarantine_proof::prove_unreachable(agent_pid);
        if !proof.ok {
            tracing::warn!(
                agent_pid = %agent_pid,
                proof = %proof.to_json(),
                "QUARANTINE_FAILED: reachable consequence remains after epoch bump"
            );
        }
        self.get_or_create(agent_pid).bump_epoch()
    }

    pub fn remove(&self, agent_pid: &str) {
        if let Ok(mut map) = self.inner.write() {
            map.remove(agent_pid.trim());
        }
    }

    pub fn len(&self) -> usize {
        self.inner.read().map(|m| m.len()).unwrap_or(0)
    }

    /// Drop cells idle longer than `max_idle` (playground hygiene).
    pub fn reap_idle(&self, max_idle: Duration) -> usize {
        let now = Instant::now();
        let mut removed = 0usize;
        let Ok(mut map) = self.inner.write() else {
            return 0;
        };
        map.retain(|_, cell| {
            let idle = cell
                .last_touch
                .lock()
                .map(|t| now.duration_since(*t) > max_idle)
                .unwrap_or(false);
            let inflight = cell.inflight.load(Ordering::SeqCst);
            if idle && inflight == 0 {
                removed += 1;
                false
            } else {
                true
            }
        });
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_bump_invalidates_read_set() {
        let cell = IntelligenceCell::new("agt_test");
        cell.stamp_read_set(vec!["cid1".into()], vec!["m/x".into()]);
        assert!(cell.read_set_fresh());
        cell.bump_epoch();
        assert!(!cell.read_set_fresh());
    }

    #[test]
    fn inflight_cap_enforced() {
        std::env::set_var("CONNECTOR_I_INFLIGHT", "2");
        let cell = Arc::new(IntelligenceCell::new("agt_cap"));
        let _a = InflightGuard::try_acquire(Arc::clone(&cell)).unwrap();
        let _b = InflightGuard::try_acquire(Arc::clone(&cell)).unwrap();
        assert!(InflightGuard::try_acquire(Arc::clone(&cell)).is_err());
        std::env::remove_var("CONNECTOR_I_INFLIGHT");
    }

    #[test]
    fn registry_get_or_create_stable() {
        let reg = CellRegistry::default();
        let a = reg.get_or_create("pid1");
        let b = reg.get_or_create("pid1");
        assert!(Arc::ptr_eq(&a, &b));
        a.bump_epoch();
        assert_eq!(b.current_epoch(), a.current_epoch());
    }
}
