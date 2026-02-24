//! NATS event bus implementation using async-nats.
//!
//! Suitable for Small-Large tier (100-1M agents) where cells run across
//! multiple processes/machines. Uses NATS JetStream for durable message delivery.
//!
//! Gated behind the `nats` feature flag.

#[cfg(feature = "nats")]
mod inner {
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;

    use async_nats::Client;
    use async_trait::async_trait;
    use tracing::{debug, warn};

    use crate::error::{BusError, BusResult};
    use crate::traits::{BusReceiver, EventBus};
    use crate::types::ReplicationEvent;

    /// NATS-backed event bus for distributed clusters.
    ///
    /// Each topic maps to a NATS subject. Events are serialized as JSON.
    /// Subscribers receive events via NATS subscriptions bridged to `BusReceiver`.
    pub struct NatsBus {
        client: Client,
        /// Subject prefix (e.g. "vac.cluster" -> topics become "vac.cluster.{topic}")
        prefix: String,
        open: Arc<AtomicBool>,
        published: Arc<AtomicU64>,
        subscriptions: Arc<AtomicUsize>,
    }

    impl NatsBus {
        /// Connect to a NATS server and create a bus with the given subject prefix.
        ///
        /// # Example
        /// ```ignore
        /// let bus = NatsBus::connect("nats://localhost:4222", "vac.cluster").await?;
        /// ```
        pub async fn connect(url: &str, prefix: &str) -> BusResult<Self> {
            let client = async_nats::connect(url)
                .await
                .map_err(|e| BusError::Connection(format!("NATS connect failed: {}", e)))?;

            debug!(url = %url, prefix = %prefix, "Connected to NATS");

            Ok(Self {
                client,
                prefix: prefix.to_string(),
                open: Arc::new(AtomicBool::new(true)),
                published: Arc::new(AtomicU64::new(0)),
                subscriptions: Arc::new(AtomicUsize::new(0)),
            })
        }

        /// Build the full NATS subject from a topic name.
        fn subject(&self, topic: &str) -> String {
            format!("{}.{}", self.prefix, topic)
        }
    }

    #[async_trait]
    impl EventBus for NatsBus {
        async fn publish(&self, topic: &str, event: &ReplicationEvent) -> BusResult<()> {
            if !self.open.load(Ordering::Relaxed) {
                return Err(BusError::Closed);
            }

            let subject = self.subject(topic);
            let payload = serde_json::to_vec(event)
                .map_err(|e| BusError::Serialization(format!("JSON encode: {}", e)))?;

            self.client
                .publish(subject.clone(), payload.into())
                .await
                .map_err(|e| BusError::PublishFailed(format!("NATS publish to {}: {}", subject, e)))?;

            self.published.fetch_add(1, Ordering::Relaxed);
            debug!(
                subject = %subject,
                op = %event.op.op_type(),
                cell = %event.cell_id,
                seq = event.seq,
                "Published to NATS"
            );
            Ok(())
        }

        async fn subscribe(&self, topic: &str) -> BusResult<BusReceiver> {
            if !self.open.load(Ordering::Relaxed) {
                return Err(BusError::Closed);
            }

            let subject = self.subject(topic);
            let mut nats_sub = self
                .client
                .subscribe(subject.clone())
                .await
                .map_err(|e| {
                    BusError::SubscribeFailed(format!("NATS subscribe to {}: {}", subject, e))
                })?;

            let (mpsc_tx, mpsc_rx) =
                tokio::sync::mpsc::channel::<ReplicationEvent>(1024);

            let open = self.open.clone();
            let sub_count = self.subscriptions.clone();
            let subj = subject.clone();

            sub_count.fetch_add(1, Ordering::Relaxed);

            tokio::spawn(async move {
                use futures::StreamExt;
                while let Some(msg) = nats_sub.next().await {
                    if !open.load(Ordering::Relaxed) {
                        break;
                    }
                    match serde_json::from_slice::<ReplicationEvent>(&msg.payload) {
                        Ok(event) => {
                            if mpsc_tx.send(event).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => {
                            warn!(
                                subject = %subj,
                                error = %e,
                                "Failed to deserialize NATS message"
                            );
                        }
                    }
                }
                sub_count.fetch_sub(1, Ordering::Relaxed);
            });

            debug!(subject = %subject, "Subscribed to NATS");
            Ok(BusReceiver::new(mpsc_rx))
        }

        async fn close(&self) -> BusResult<()> {
            self.open.store(false, Ordering::Relaxed);
            debug!("NatsBus closed");
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

}

#[cfg(feature = "nats")]
pub use inner::NatsBus;
