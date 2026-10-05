//! In-process event bus using tokio broadcast channels.
//!
//! Suitable for Nano/Micro tier (1-100 agents) where all cells
//! run in the same process. Zero network overhead.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::{broadcast, RwLock};
use tracing::{debug, warn};

use crate::error::{BusError, BusResult};
use crate::traits::{BusReceiver, EventBus};
use crate::types::ReplicationEvent;

/// Default capacity for broadcast channels per topic.
///
/// Raised from 1024 → 16384 (Gap 2 fix, infra.md §3).
/// At T1 (100K ops/sec, receiver at 80K ops/sec):
///   old: queue fills in 1024 / 20K = ~50ms → silent data loss
///   new: queue fills in 16384 / 20K = ~820ms → time to detect and sync
const DEFAULT_CHANNEL_CAPACITY: usize = 16_384;

/// Tier-aware capacities — set via `InProcessBus::with_tier_capacity`.
pub const CAPACITY_NANO: usize = 16_384;
pub const CAPACITY_MICRO: usize = 65_536;

/// Global lag event counter — incremented on every RecvError::Lagged.
/// Exposed via GET /metrics as `vac_bus_lag_total`.
static LAG_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Returns the total number of lag events since process start.
pub fn lag_counter() -> u64 {
    LAG_COUNTER.load(std::sync::atomic::Ordering::Relaxed)
}

/// In-process event bus backed by tokio broadcast channels.
///
/// Each topic gets its own broadcast channel. Subscribers receive
/// cloned events. No serialization overhead — events are passed by clone.
pub struct InProcessBus {
    /// Map of topic -> broadcast sender
    topics: Arc<RwLock<HashMap<String, broadcast::Sender<ReplicationEvent>>>>,
    /// Channel capacity per topic
    capacity: usize,
    /// Whether the bus is open
    open: Arc<AtomicBool>,
    /// Total events published
    published: Arc<AtomicU64>,
    /// Active subscription count
    subscriptions: Arc<AtomicUsize>,
}

impl InProcessBus {
    /// Create a new InProcessBus with default channel capacity (1024).
    pub fn new() -> Self {
        Self {
            topics: Arc::new(RwLock::new(HashMap::new())),
            capacity: DEFAULT_CHANNEL_CAPACITY,
            open: Arc::new(AtomicBool::new(true)),
            published: Arc::new(AtomicU64::new(0)),
            subscriptions: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Create a new InProcessBus with a custom channel capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            topics: Arc::new(RwLock::new(HashMap::new())),
            capacity,
            open: Arc::new(AtomicBool::new(true)),
            published: Arc::new(AtomicU64::new(0)),
            subscriptions: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Get or create a broadcast sender for a topic.
    async fn get_or_create_sender(
        &self,
        topic: &str,
    ) -> broadcast::Sender<ReplicationEvent> {
        // Fast path: read lock
        {
            let topics = self.topics.read().await;
            if let Some(sender) = topics.get(topic) {
                return sender.clone();
            }
        }
        // Slow path: write lock, create channel
        let mut topics = self.topics.write().await;
        // Double-check after acquiring write lock
        if let Some(sender) = topics.get(topic) {
            return sender.clone();
        }
        let (tx, _rx) = broadcast::channel(self.capacity);
        debug!(topic = %topic, capacity = self.capacity, "Created broadcast channel");
        topics.insert(topic.to_string(), tx.clone());
        tx
    }

    /// Returns the number of topics that have been created.
    pub async fn topic_count(&self) -> usize {
        self.topics.read().await.len()
    }
}

impl Default for InProcessBus {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl EventBus for InProcessBus {
    async fn publish(&self, topic: &str, event: &ReplicationEvent) -> BusResult<()> {
        if !self.open.load(Ordering::Relaxed) {
            return Err(BusError::Closed);
        }

        let sender = self.get_or_create_sender(topic).await;

        // broadcast::send returns Err only if there are no receivers,
        // which is fine — we just drop the event silently.
        match sender.send(event.clone()) {
            Ok(receiver_count) => {
                self.published.fetch_add(1, Ordering::Relaxed);
                debug!(
                    topic = %topic,
                    op = %event.op.op_type(),
                    cell = %event.cell_id,
                    seq = event.seq,
                    receivers = receiver_count,
                    "Published event"
                );
                Ok(())
            }
            Err(_) => {
                // No receivers — still count as published (fire-and-forget)
                self.published.fetch_add(1, Ordering::Relaxed);
                debug!(
                    topic = %topic,
                    op = %event.op.op_type(),
                    "Published event (no receivers)"
                );
                Ok(())
            }
        }
    }

    async fn subscribe(&self, topic: &str) -> BusResult<BusReceiver> {
        if !self.open.load(Ordering::Relaxed) {
            return Err(BusError::Closed);
        }

        let sender = self.get_or_create_sender(topic).await;
        let mut broadcast_rx = sender.subscribe();

        // Bridge broadcast::Receiver -> mpsc::Receiver via a spawned task.
        // This is needed because broadcast::Receiver doesn't implement Send
        // in a way that's easy to return from an async trait method.
        let (mpsc_tx, mpsc_rx) = tokio::sync::mpsc::channel::<ReplicationEvent>(self.capacity);

        let open = self.open.clone();
        let sub_count = self.subscriptions.clone();
        let topic_name = topic.to_string();

        sub_count.fetch_add(1, Ordering::Relaxed);

        tokio::spawn(async move {
            loop {
                if !open.load(Ordering::Relaxed) {
                    break;
                }
                match broadcast_rx.recv().await {
                    Ok(event) => {
                        if mpsc_tx.send(event).await.is_err() {
                            // Receiver dropped
                            break;
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        // Increment global lag counter (exported as Prometheus metric)
                        LAG_COUNTER.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
                        warn!(
                            topic = %topic_name,
                            lagged = n,
                            lag_total = LAG_COUNTER.load(std::sync::atomic::Ordering::Relaxed),
                            "Subscriber lagged — {} events dropped. Merkle sync required.",
                            n
                        );
                        // Send a synthetic Heartbeat event to trigger Merkle sync
                        // on the receiver side. The receiver pattern-matches on
                        // ReplicationOp::Heartbeat and can trigger TriggerSync.
                        let sync_event = crate::types::ReplicationEvent {
                            cell_id: "__lag_sync__".to_string(),
                            seq: 0,
                            op: crate::types::ReplicationOp::Heartbeat {
                                agent_count: 0,
                                packet_count: 0,
                                merkle_root: [0u8; 32],
                                load: 100,
                            },
                            signature: vec![],
                            ts: std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_millis() as i64,
                        };
                        let _ = mpsc_tx.send(sync_event).await;
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        break;
                    }
                }
            }
            sub_count.fetch_sub(1, Ordering::Relaxed);
        });

        debug!(topic = %topic, "New subscription");
        Ok(BusReceiver::new(mpsc_rx))
    }

    async fn close(&self) -> BusResult<()> {
        self.open.store(false, Ordering::Relaxed);
        // Drop all senders, which will close all broadcast channels
        let mut topics = self.topics.write().await;
        topics.clear();
        debug!("Bus closed");
        Ok(())
    }

    fn is_open(&self) -> bool {
        self.open.load(Ordering::Relaxed)
    }

    fn subscription_count(&self) -> usize {
        self.subscriptions.load(Ordering::Relaxed)
    }

    fn published_count(&self) -> u64 {
        self.published.load(Ordering::Relaxed)
    }
}
