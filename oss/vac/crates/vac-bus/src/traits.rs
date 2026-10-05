//! Core trait for event bus implementations.

use async_trait::async_trait;

use crate::error::BusResult;
use crate::types::ReplicationEvent;

/// Receiver handle for consuming events from a topic subscription.
///
/// Wraps a `tokio::sync::mpsc::Receiver` so that implementations can
/// convert their native receiver into this common type.
pub struct BusReceiver {
    inner: tokio::sync::mpsc::Receiver<ReplicationEvent>,
}

impl BusReceiver {
    /// Create a new BusReceiver wrapping an mpsc receiver.
    pub fn new(rx: tokio::sync::mpsc::Receiver<ReplicationEvent>) -> Self {
        Self { inner: rx }
    }

    /// Receive the next event, returning None if the channel is closed.
    pub async fn recv(&mut self) -> Option<ReplicationEvent> {
        self.inner.recv().await
    }

    /// Try to receive an event without blocking.
    pub fn try_recv(&mut self) -> Option<ReplicationEvent> {
        self.inner.try_recv().ok()
    }
}

/// Core trait for all event bus implementations.
///
/// The bus provides pub/sub messaging between cells in a cluster.
/// Topics are strings like `"cluster.replication"`, `"cell.{id}.vakya"`, etc.
///
/// Implementations:
/// - `InProcessBus`: tokio broadcast channels (Nano/Micro tier, 1-100 agents)
/// - NatsBus: async-nats + JetStream (Small-Large tier, future)
/// - KafkaBus: rdkafka (Planetary tier, future)
#[async_trait]
pub trait EventBus: Send + Sync + 'static {
    /// Publish an event to a topic.
    ///
    /// For InProcessBus this is instant. For NatsBus this publishes to NATS.
    /// The event should be signed before publishing.
    async fn publish(&self, topic: &str, event: &ReplicationEvent) -> BusResult<()>;

    /// Subscribe to a topic and receive events via a BusReceiver.
    ///
    /// Multiple subscribers to the same topic each get their own copy of events.
    /// The returned BusReceiver yields events until the bus is closed.
    async fn subscribe(&self, topic: &str) -> BusResult<BusReceiver>;

    /// Close the bus, stopping all subscriptions.
    async fn close(&self) -> BusResult<()>;

    /// Returns true if the bus is still open and operational.
    fn is_open(&self) -> bool;

    /// Returns the number of active subscriptions across all topics.
    fn subscription_count(&self) -> usize;

    /// Returns the total number of events published since bus creation.
    fn published_count(&self) -> u64;
}
