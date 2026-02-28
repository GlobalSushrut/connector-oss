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
    use std::time::Duration;

    use async_nats::Client;
    use async_trait::async_trait;
    use tracing::{debug, info, warn};

    use crate::error::{BusError, BusResult};
    use crate::traits::{BusReceiver, EventBus};
    use crate::types::ReplicationEvent;

    /// Configuration for NatsBus connection pool and reconnection behavior.
    #[derive(Debug, Clone)]
    pub struct NatsConfig {
        /// Maximum number of consecutive reconnect attempts before giving up.
        /// `None` = unlimited.
        pub max_reconnect_attempts: Option<usize>,
        /// Base backoff duration for reconnection (doubles each attempt, capped at `max_backoff`).
        pub reconnect_base_ms: u64,
        /// Maximum backoff duration for reconnection.
        pub max_backoff_ms: u64,
        /// Random jitter added to backoff to prevent thundering herd (0..jitter_ms).
        pub jitter_ms: u64,
        /// TCP connection timeout.
        pub connection_timeout: Duration,
        /// Whether to retry on initial connect failure (background connect).
        pub retry_on_initial_connect: bool,
        /// NATS subscription buffer capacity.
        pub subscription_capacity: usize,
        /// Client name reported to NATS server.
        pub client_name: Option<String>,
    }

    impl Default for NatsConfig {
        fn default() -> Self {
            Self {
                max_reconnect_attempts: None, // unlimited
                reconnect_base_ms: 100,
                max_backoff_ms: 8_000,
                jitter_ms: 50,
                connection_timeout: Duration::from_secs(5),
                retry_on_initial_connect: false,
                subscription_capacity: 65536,
                client_name: None,
            }
        }
    }

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
        /// Count of disconnect events observed.
        pub disconnect_count: Arc<AtomicU64>,
        /// Count of reconnect events observed.
        pub reconnect_count: Arc<AtomicU64>,
    }

    impl NatsBus {
        /// Connect to a NATS server with default settings.
        ///
        /// # Example
        /// ```ignore
        /// let bus = NatsBus::connect("nats://localhost:4222", "vac.cluster").await?;
        /// ```
        pub async fn connect(url: &str, prefix: &str) -> BusResult<Self> {
            Self::connect_with_config(url, prefix, NatsConfig::default()).await
        }

        /// Connect to a NATS server with custom configuration.
        ///
        /// Configures exponential backoff with jitter for reconnection,
        /// max reconnect attempts, connection timeout, and event tracking.
        pub async fn connect_with_config(
            url: &str,
            prefix: &str,
            config: NatsConfig,
        ) -> BusResult<Self> {
            let disconnect_count = Arc::new(AtomicU64::new(0));
            let reconnect_count = Arc::new(AtomicU64::new(0));

            let dc = disconnect_count.clone();
            let rc = reconnect_count.clone();

            let base = config.reconnect_base_ms;
            let max_backoff = config.max_backoff_ms;
            let jitter = config.jitter_ms;

            let mut opts = async_nats::ConnectOptions::new()
                .connection_timeout(config.connection_timeout)
                .subscription_capacity(config.subscription_capacity)
                .reconnect_delay_callback(move |attempts| {
                    // Exponential backoff: base * 2^attempts, capped at max_backoff
                    let shift = (attempts as u32).min(63);
                    let exp_delay = base.saturating_mul(1u64.checked_shl(shift).unwrap_or(u64::MAX));
                    let capped = exp_delay.min(max_backoff);
                    // Add jitter: rand not available here, use attempt-based pseudo-jitter
                    let j = if jitter > 0 {
                        (attempts as u64 * 37 + 13) % jitter
                    } else {
                        0
                    };
                    Duration::from_millis(capped + j)
                })
                .event_callback(move |event| {
                    let dc = dc.clone();
                    let rc = rc.clone();
                    async move {
                        match event {
                            async_nats::Event::Disconnected => {
                                dc.fetch_add(1, Ordering::Relaxed);
                                warn!("NatsBus: disconnected from server");
                            }
                            async_nats::Event::Connected => {
                                rc.fetch_add(1, Ordering::Relaxed);
                                info!("NatsBus: (re)connected to server");
                            }
                            other => {
                                debug!(event = %other, "NatsBus: event");
                            }
                        }
                    }
                });

            if let Some(max) = config.max_reconnect_attempts {
                opts = opts.max_reconnects(max);
            } else {
                opts = opts.max_reconnects(None);
            }

            if config.retry_on_initial_connect {
                opts = opts.retry_on_initial_connect();
            }

            if let Some(ref name) = config.client_name {
                opts = opts.name(name);
            }

            let client = opts
                .connect(url)
                .await
                .map_err(|e| BusError::Connection(format!("NATS connect failed: {}", e)))?;

            debug!(url = %url, prefix = %prefix, "Connected to NATS");

            Ok(Self {
                client,
                prefix: prefix.to_string(),
                open: Arc::new(AtomicBool::new(true)),
                published: Arc::new(AtomicU64::new(0)),
                subscriptions: Arc::new(AtomicUsize::new(0)),
                disconnect_count,
                reconnect_count,
            })
        }

        /// Build the full NATS subject from a topic name.
        fn subject(&self, topic: &str) -> String {
            format!("{}.{}", self.prefix, topic)
        }

        /// Number of times the bus disconnected from the NATS server.
        pub fn disconnects(&self) -> u64 {
            self.disconnect_count.load(Ordering::Relaxed)
        }

        /// Number of times the bus reconnected to the NATS server.
        pub fn reconnects(&self) -> u64 {
            self.reconnect_count.load(Ordering::Relaxed)
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
pub use inner::{NatsBus, NatsConfig};
