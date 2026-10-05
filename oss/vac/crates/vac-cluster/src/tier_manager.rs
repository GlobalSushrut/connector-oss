//! # I12 — TierManager: automated bus/cell tier promotion
//!
//! Monitors ops/sec + agent count and automatically promotes the cluster tier:
//!   T0 → T1: agents > 8 OR ops/sec > 50K → increase InProcessBus capacity
//!   T1 → T2: agents > 80 OR ops/sec > 400K → provision NATS, spawn second Cell
//!
//! The TierManager runs as a background tokio task, sampling every 10 seconds.
//! Promotion is idempotent and uses atomic CAS to prevent double-promotion.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

/// Current deployment tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Tier {
    /// Single node, InProcessBus, no WAL
    T0 = 0,
    /// Up to ~10 agents, InProcessBus with expanded capacity, WAL enabled
    T1 = 1,
    /// Up to ~100 agents, NATS bus, multi-cell, WAL + replication
    T2 = 2,
    /// Enterprise: federation, cross-region, full replication
    T3 = 3,
}

impl Tier {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::T0,
            1 => Self::T1,
            2 => Self::T2,
            _ => Self::T3,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::T0 => "T0 (single-node, InProcessBus)",
            Self::T1 => "T1 (expanded bus, WAL enabled)",
            Self::T2 => "T2 (NATS bus, multi-cell)",
            Self::T3 => "T3 (enterprise federation)",
        }
    }
}

/// Thresholds that trigger tier promotion.
#[derive(Debug, Clone)]
pub struct TierThresholds {
    /// Agent count that triggers T0→T1 promotion
    pub t0_to_t1_agents: u64,
    /// ops/sec that triggers T0→T1 promotion
    pub t0_to_t1_ops_per_sec: f64,
    /// Agent count that triggers T1→T2 promotion
    pub t1_to_t2_agents: u64,
    /// ops/sec that triggers T1→T2 promotion
    pub t1_to_t2_ops_per_sec: f64,
}

impl Default for TierThresholds {
    fn default() -> Self {
        Self {
            t0_to_t1_agents: 8,
            t0_to_t1_ops_per_sec: 50_000.0,
            t1_to_t2_agents: 80,
            t1_to_t2_ops_per_sec: 400_000.0,
        }
    }
}

/// Shared tier state — can be read by any component.
#[derive(Clone)]
pub struct TierState {
    current: Arc<AtomicU8>,
}

impl TierState {
    pub fn new(initial: Tier) -> Self {
        Self {
            current: Arc::new(AtomicU8::new(initial as u8)),
        }
    }

    pub fn get(&self) -> Tier {
        Tier::from_u8(self.current.load(Ordering::Acquire))
    }

    /// CAS promote to `next` from `expected`. Returns true if promoted.
    pub fn promote(&self, expected: Tier, next: Tier) -> bool {
        self.current
            .compare_exchange(
                expected as u8,
                next as u8,
                Ordering::AcqRel,
                Ordering::Relaxed,
            )
            .is_ok()
    }
}

/// Snapshot of cluster metrics used for tier decisions.
#[derive(Debug, Clone, Default)]
pub struct TierMetricsSnapshot {
    pub agent_count: u64,
    pub ops_per_sec: f64,
}

/// Trait for the metrics source — implemented by the platform server state.
pub trait TierMetricsSource: Send + Sync + 'static {
    fn snapshot(&self) -> TierMetricsSnapshot;
}

/// Tier promotion callback — called when a tier change occurs.
pub trait TierPromotionHook: Send + Sync + 'static {
    fn on_promote(&self, from: Tier, to: Tier);
}

/// Noop hook for testing/dev mode.
pub struct NoopHook;
impl TierPromotionHook for NoopHook {
    fn on_promote(&self, from: Tier, to: Tier) {
        info!(
            from = ?from,
            to = ?to,
            "[TierManager] Tier promoted: {} → {}",
            from.name(), to.name()
        );
    }
}

/// The TierManager — spawns a background loop that checks metrics and promotes tiers.
pub struct TierManager<M: TierMetricsSource, H: TierPromotionHook> {
    state: TierState,
    thresholds: TierThresholds,
    metrics: Arc<M>,
    hook: Arc<H>,
    poll_secs: u64,
}

impl<M: TierMetricsSource, H: TierPromotionHook> TierManager<M, H> {
    pub fn new(
        initial_tier: Tier,
        metrics: M,
        hook: H,
        thresholds: TierThresholds,
        poll_secs: u64,
    ) -> Self {
        Self {
            state: TierState::new(initial_tier),
            thresholds,
            metrics: Arc::new(metrics),
            hook: Arc::new(hook),
            poll_secs,
        }
    }

    /// Current tier.
    pub fn tier(&self) -> Tier {
        self.state.get()
    }

    /// Shared tier state handle for cross-component access.
    pub fn tier_state(&self) -> TierState {
        self.state.clone()
    }

    /// Start the background promotion loop. Returns a `JoinHandle`.
    pub fn start(self) -> tokio::task::JoinHandle<()> {
        let state = self.state;
        let thresholds = self.thresholds;
        let metrics = self.metrics;
        let hook = self.hook;
        let poll_secs = self.poll_secs;

        tokio::spawn(async move {
            info!("[TierManager] Started (poll={}s, initial={})", poll_secs, state.get().name());
            loop {
                tokio::time::sleep(tokio::time::Duration::from_secs(poll_secs)).await;

                let snap = metrics.snapshot();
                let current = state.get();

                match current {
                    Tier::T0 => {
                        let should_promote =
                            snap.agent_count > thresholds.t0_to_t1_agents
                            || snap.ops_per_sec > thresholds.t0_to_t1_ops_per_sec;

                        if should_promote {
                            if state.promote(Tier::T0, Tier::T1) {
                                info!(
                                    agents = snap.agent_count,
                                    ops_per_sec = snap.ops_per_sec,
                                    "[TierManager] T0→T1: expanding InProcessBus capacity + enabling WAL"
                                );
                                hook.on_promote(Tier::T0, Tier::T1);
                            }
                        }
                    }

                    Tier::T1 => {
                        let should_promote =
                            snap.agent_count > thresholds.t1_to_t2_agents
                            || snap.ops_per_sec > thresholds.t1_to_t2_ops_per_sec;

                        if should_promote {
                            if state.promote(Tier::T1, Tier::T2) {
                                warn!(
                                    agents = snap.agent_count,
                                    ops_per_sec = snap.ops_per_sec,
                                    "[TierManager] T1→T2: provisioning NATS bus + second Cell. \
                                    Ensure NATS_URL is set. WAL replication will start automatically."
                                );
                                hook.on_promote(Tier::T1, Tier::T2);
                            }
                        }
                    }

                    Tier::T2 | Tier::T3 => {
                        // T2→T3 requires manual operator action (federation config)
                    }
                }
            }
        })
    }
}
