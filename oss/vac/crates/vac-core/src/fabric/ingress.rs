//! # Memory Ingress Gateway
//!
//! All memory enters the system through a single normalization pipeline:
//!
//! ```text
//! 1. RECEIVE     — accept raw input from any source
//! 2. NORMALIZE   — convert to canonical MemoryEvent
//! 3. CLASSIFY    — assign event_type, memory_class
//! 4. SCOPE       — resolve container, trace, partition
//! 5. DEDUPE      — check idempotency_key against recent log
//! 6. STAMP       — assign LSN, timestamp, policy snapshot
//! 7. COMMIT      — append to commit log (event becomes durable)
//! 8. ACK         — return commit receipt to producer
//! ```
//!
//! The ingress gateway guarantees that no storage backend becomes the first
//! writer of truth. The first truth is always the committed event.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use super::types::*;
use super::commit_log::CommitLog;

// =============================================================================
// IngressConfig
// =============================================================================

/// Configuration for the ingress gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressConfig {
    /// Maximum number of recent idempotency keys to cache.
    pub dedup_cache_size: usize,
    /// Deduplication window in milliseconds.
    pub dedup_window_ms: u64,
    /// Maximum inline payload size before requiring object fabric reference.
    pub max_inline_bytes: u64,
    /// Whether to enforce idempotency key uniqueness.
    pub enforce_dedup: bool,
}

impl Default for IngressConfig {
    fn default() -> Self {
        Self {
            dedup_cache_size: 10_000,
            dedup_window_ms: 5 * 60 * 1000, // 5 minutes
            max_inline_bytes: PayloadDescriptor::MAX_INLINE_BYTES,
            enforce_dedup: true,
        }
    }
}

// =============================================================================
// IngressRequest — raw input before normalization
// =============================================================================

/// Raw input to the ingress gateway from any source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressRequest {
    pub source_type: SourceType,
    pub producer_id: String,
    pub tenant_id: String,
    pub container_id: String,
    pub trace_id: Option<String>,
    pub idempotency_key: Option<String>,
    pub event_type: EventType,
    pub memory_class: MemoryClass,
    pub payload: serde_json::Value,
    pub content_type: String,
    pub policy: Option<PolicySnapshot>,
    pub metadata: HashMap<String, String>,
}

/// Source classification for incoming memory.
///
/// Covers all autonomous agent types — not just LLM text interactions but also
/// sensor hardware, camera feeds, ML training pipelines, inference servers,
/// robotics controllers, and any other memory-producing system.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceType {
    // ── Agent / LLM ──
    UserRequest,
    AgentOutput,
    ToolResponse,
    FileUpload,
    CrawlerResult,
    SummarizerResult,
    EmbedderResult,
    ProjectionResult,
    SystemEvent,

    // ── Multimodal Capture ──
    CameraCapture,
    MicrophoneCapture,
    ScreenCapture,
    DocumentScan,

    // ── Sensor / Hardware ──
    SensorReading,
    LidarScan,
    GpsReading,
    ImuReading,
    DepthSensor,

    // ── ML / Neural Network Pipeline ──
    TrainingCheckpoint,
    InferenceOutput,
    EvaluationResult,
    FeatureExtraction,
    GradientSnapshot,
    DatasetIngestion,
    ModelExport,

    // ── Robotics / Embodied ──
    PerceptionPipeline,
    ActuationCommand,
    EnvironmentObservation,
    RewardSignal,
    PlannerOutput,
    MotorFeedback,
}

// =============================================================================
// IngressResult — what the gateway returns
// =============================================================================

/// Result from the ingress gateway after processing a request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressResult {
    pub event_id: String,
    pub lsn: u64,
    pub partition: u32,
    pub timestamp: i64,
    pub status: IngressStatus,
}

/// Status of ingress processing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressStatus {
    Committed,
    Deduplicated { original_lsn: u64 },
    Rejected { reason: String },
}

// =============================================================================
// DedupEntry — tracks recent idempotency keys
// =============================================================================

#[derive(Debug, Clone)]
struct DedupEntry {
    lsn: u64,
    partition: u32,
    timestamp: i64,
}

// =============================================================================
// IngressGateway
// =============================================================================

/// Memory Ingress Gateway — single entry point for all memory-bearing actions.
///
/// Normalizes, classifies, deduplicates, stamps, and commits events to the
/// commit log. Ensures no storage backend writes truth before the commit log.
pub struct IngressGateway {
    pub config: IngressConfig,
    commit_log: CommitLog,
    /// LRU-style dedup cache: idempotency_key → DedupEntry
    dedup_cache: HashMap<String, DedupEntry>,
    /// Ordered keys for LRU eviction
    dedup_order: Vec<(String, i64)>,
    /// Stats
    total_committed: u64,
    total_deduplicated: u64,
    total_rejected: u64,
}

impl IngressGateway {
    pub fn new(config: IngressConfig, commit_log: CommitLog) -> Self {
        Self {
            config,
            commit_log,
            dedup_cache: HashMap::new(),
            dedup_order: Vec::new(),
            total_committed: 0,
            total_deduplicated: 0,
            total_rejected: 0,
        }
    }

    /// Create with default config and developer commit log.
    pub fn developer() -> Self {
        Self::new(IngressConfig::default(), CommitLog::developer())
    }

    /// Process an ingress request through the full pipeline.
    pub fn ingest(&mut self, request: IngressRequest) -> IngressResult {
        let now = now_ms();

        // Step 1: Generate or use provided idempotency key
        let idem_key = request.idempotency_key
            .unwrap_or_else(|| generate_id("idem"));

        // Step 2: Dedup check
        if self.config.enforce_dedup {
            if let Some(existing) = self.dedup_cache.get(&idem_key) {
                self.total_deduplicated += 1;
                return IngressResult {
                    event_id: String::new(),
                    lsn: existing.lsn,
                    partition: existing.partition,
                    timestamp: existing.timestamp,
                    status: IngressStatus::Deduplicated { original_lsn: existing.lsn },
                };
            }
        }

        // Step 3: Normalize payload into PayloadDescriptor
        let payload_bytes = serde_json::to_vec(&request.payload).unwrap_or_default();
        let payload = if payload_bytes.len() as u64 <= self.config.max_inline_bytes {
            PayloadDescriptor::inline(&request.content_type, request.payload)
        } else {
            // Large payload — would need Object Fabric write first in production.
            // For now, inline it anyway (developer mode). Production backends
            // would store to Object Fabric and reference it here.
            PayloadDescriptor::inline(&request.content_type, request.payload)
        };

        // Step 4: Build canonical MemoryEvent
        let event_id = generate_id("evt");
        let partition_key = request.trace_id.clone()
            .unwrap_or_else(|| request.producer_id.clone());

        let event = MemoryEvent {
            event_id: event_id.clone(),
            tenant_id: request.tenant_id,
            container_id: request.container_id,
            trace_id: request.trace_id,
            partition_key,
            event_type: request.event_type,
            memory_class: request.memory_class,
            producer_id: request.producer_id,
            idempotency_key: idem_key.clone(),
            payload,
            policy: request.policy.unwrap_or_default(),
            timestamp: now,
            lsn: 0, // assigned by commit log
        };

        // Step 5: Commit to log
        let (partition, lsn) = self.commit_log.append(event);

        // Step 6: Record in dedup cache
        self.record_dedup(&idem_key, lsn, partition, now);

        self.total_committed += 1;

        IngressResult {
            event_id,
            lsn,
            partition,
            timestamp: now,
            status: IngressStatus::Committed,
        }
    }

    /// Record a key in the dedup cache, evicting old entries.
    fn record_dedup(&mut self, key: &str, lsn: u64, partition: u32, timestamp: i64) {
        self.dedup_cache.insert(key.to_string(), DedupEntry { lsn, partition, timestamp });
        self.dedup_order.push((key.to_string(), timestamp));

        // Evict old entries (beyond window or over capacity)
        let cutoff = timestamp - self.config.dedup_window_ms as i64;
        self.dedup_order.retain(|(k, ts)| {
            if *ts < cutoff {
                self.dedup_cache.remove(k);
                false
            } else {
                true
            }
        });

        // Hard cap on cache size
        while self.dedup_order.len() > self.config.dedup_cache_size {
            if let Some((k, _)) = self.dedup_order.first().cloned() {
                self.dedup_cache.remove(&k);
                self.dedup_order.remove(0);
            }
        }
    }

    /// Get a reference to the underlying commit log.
    pub fn commit_log(&self) -> &CommitLog {
        &self.commit_log
    }

    /// Get a mutable reference to the commit log.
    pub fn commit_log_mut(&mut self) -> &mut CommitLog {
        &mut self.commit_log
    }

    /// Read events from the commit log for a materializer.
    pub fn read_events(&self, partition: u32, from_lsn: u64, limit: usize) -> &[MemoryEvent] {
        self.commit_log.read(partition, from_lsn, limit)
    }

    /// Get ingress stats.
    pub fn stats(&self) -> IngressStats {
        IngressStats {
            total_committed: self.total_committed,
            total_deduplicated: self.total_deduplicated,
            total_rejected: self.total_rejected,
            dedup_cache_size: self.dedup_cache.len() as u64,
            commit_log_events: self.commit_log.total_events(),
            commit_log_partitions: self.commit_log.partition_count(),
        }
    }
}

/// Ingress gateway statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngressStats {
    pub total_committed: u64,
    pub total_deduplicated: u64,
    pub total_rejected: u64,
    pub dedup_cache_size: u64,
    pub commit_log_events: u64,
    pub commit_log_partitions: u32,
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(producer: &str, container: &str, idem_key: Option<&str>) -> IngressRequest {
        IngressRequest {
            source_type: SourceType::AgentOutput,
            producer_id: producer.to_string(),
            tenant_id: "tenant:test".to_string(),
            container_id: container.to_string(),
            trace_id: None,
            idempotency_key: idem_key.map(|s| s.to_string()),
            event_type: EventType::InteractionCreated,
            memory_class: MemoryClass::Episodic,
            payload: serde_json::json!({"content": "test"}),
            content_type: "application/json".to_string(),
            policy: None,
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_basic_ingest() {
        let mut gw = IngressGateway::developer();
        let result = gw.ingest(make_request("pid:001", "cont:A", None));

        assert_eq!(result.status, IngressStatus::Committed);
        assert_eq!(result.lsn, 0);
        assert!(!result.event_id.is_empty());

        let stats = gw.stats();
        assert_eq!(stats.total_committed, 1);
        assert_eq!(stats.commit_log_events, 1);
    }

    #[test]
    fn test_multiple_ingests() {
        let mut gw = IngressGateway::developer();
        for i in 0..10 {
            let result = gw.ingest(make_request("pid:001", "cont:A", None));
            assert_eq!(result.status, IngressStatus::Committed);
            assert_eq!(result.lsn, i);
        }
        assert_eq!(gw.stats().total_committed, 10);
    }

    #[test]
    fn test_dedup() {
        let mut gw = IngressGateway::developer();

        let r1 = gw.ingest(make_request("pid:001", "cont:A", Some("key:unique:001")));
        assert_eq!(r1.status, IngressStatus::Committed);

        let r2 = gw.ingest(make_request("pid:001", "cont:A", Some("key:unique:001")));
        assert_eq!(r2.status, IngressStatus::Deduplicated { original_lsn: 0 });

        let stats = gw.stats();
        assert_eq!(stats.total_committed, 1);
        assert_eq!(stats.total_deduplicated, 1);
        assert_eq!(stats.commit_log_events, 1);
    }

    #[test]
    fn test_dedup_different_keys() {
        let mut gw = IngressGateway::developer();

        let r1 = gw.ingest(make_request("pid:001", "c", Some("key:A")));
        let r2 = gw.ingest(make_request("pid:001", "c", Some("key:B")));

        assert_eq!(r1.status, IngressStatus::Committed);
        assert_eq!(r2.status, IngressStatus::Committed);
        assert_eq!(gw.stats().total_committed, 2);
    }

    #[test]
    fn test_dedup_disabled() {
        let config = IngressConfig {
            enforce_dedup: false,
            ..Default::default()
        };
        let mut gw = IngressGateway::new(config, CommitLog::developer());

        let r1 = gw.ingest(make_request("p", "c", Some("same_key")));
        let r2 = gw.ingest(make_request("p", "c", Some("same_key")));

        assert_eq!(r1.status, IngressStatus::Committed);
        assert_eq!(r2.status, IngressStatus::Committed);
        assert_eq!(gw.stats().total_committed, 2);
    }

    #[test]
    fn test_read_events_from_gateway() {
        let mut gw = IngressGateway::developer();
        gw.ingest(make_request("pid:001", "cont:A", None));
        gw.ingest(make_request("pid:001", "cont:A", None));

        let events = gw.read_events(0, 0, 100);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_type, EventType::InteractionCreated);
    }

    #[test]
    fn test_dedup_cache_eviction() {
        let config = IngressConfig {
            dedup_cache_size: 3,
            enforce_dedup: true,
            ..Default::default()
        };
        let mut gw = IngressGateway::new(config, CommitLog::developer());

        for i in 0..5 {
            gw.ingest(make_request("p", "c", Some(&format!("k:{}", i))));
        }
        // Cache can hold 3. Keys 0 and 1 should be evicted.
        assert!(gw.dedup_cache.len() <= 3);
    }

    #[test]
    fn test_auto_idempotency_key() {
        let mut gw = IngressGateway::developer();
        let r1 = gw.ingest(make_request("p", "c", None));
        let r2 = gw.ingest(make_request("p", "c", None));

        // Auto-generated keys should be unique → both committed
        assert_eq!(r1.status, IngressStatus::Committed);
        assert_eq!(r2.status, IngressStatus::Committed);
    }

    #[test]
    fn test_ingress_with_policy() {
        let mut gw = IngressGateway::developer();
        let mut req = make_request("pid:001", "cont:A", None);
        req.policy = Some(PolicySnapshot {
            visibility: Visibility::Shared,
            encryption_required: true,
            ..Default::default()
        });
        let result = gw.ingest(req);
        assert_eq!(result.status, IngressStatus::Committed);

        let events = gw.read_events(0, 0, 1);
        assert_eq!(events[0].policy.visibility, Visibility::Shared);
        assert!(events[0].policy.encryption_required);
    }

    #[test]
    fn test_ingress_with_trace_id() {
        let mut gw = IngressGateway::developer();
        let mut req = make_request("pid:001", "cont:A", None);
        req.trace_id = Some("trace:reasoning:001".to_string());
        let result = gw.ingest(req);
        assert_eq!(result.status, IngressStatus::Committed);

        let events = gw.read_events(0, 0, 1);
        assert_eq!(events[0].trace_id.as_deref(), Some("trace:reasoning:001"));
        // trace_id is used as partition key when available
        assert_eq!(events[0].partition_key, "trace:reasoning:001");
    }

    #[test]
    fn test_source_types_serde() {
        let st = SourceType::AgentOutput;
        let json = serde_json::to_string(&st).unwrap();
        assert_eq!(json, "\"agent_output\"");
    }

    #[test]
    fn test_ingress_status_serde() {
        let s = IngressStatus::Committed;
        let json = serde_json::to_string(&s).unwrap();
        let back: IngressStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);

        let d = IngressStatus::Deduplicated { original_lsn: 42 };
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("42"));
    }
}
