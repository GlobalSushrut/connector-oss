//! # Memory Commit Log Fabric
//!
//! Kafka-grade ordered append-only log with partitions, offsets, consumer
//! checkpointing, and replay.
//!
//! Every memory-bearing action first becomes a **committed event** before any
//! downstream processing. Materializers consume events independently and
//! checkpoint their progress.
//!
//! ## Scaling
//!
//! | Mode | Backend | Throughput |
//! |------|---------|------------|
//! | Developer | In-memory `Vec<MemoryEvent>` | 100K events/sec |
//! | Single-server | Local append file + mmap | 500K events/sec |
//! | Production | Redpanda / Kafka | 1M+ events/sec |
//!
//! ## Industry Reference
//!
//! - Apache Kafka: topics, partitions, offsets, consumer groups, log compaction
//! - Write-Ahead Logging: LSN, checkpoints, crash recovery

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use super::types::*;

// =============================================================================
// Partition — ordered segment of a commit log
// =============================================================================

/// A single partition within a commit log stream.
///
/// Events within a partition are strictly ordered by LSN.
/// Events across partitions have no ordering guarantee.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Partition {
    pub id: u32,
    events: Vec<MemoryEvent>,
    next_lsn: u64,
    high_watermark: u64,
}

impl Partition {
    pub fn new(id: u32) -> Self {
        Self {
            id,
            events: Vec::new(),
            next_lsn: 0,
            high_watermark: 0,
        }
    }

    /// Append an event to this partition. Assigns LSN and returns it.
    pub fn append(&mut self, mut event: MemoryEvent) -> u64 {
        let lsn = self.next_lsn;
        event.lsn = lsn;
        self.next_lsn += 1;
        self.high_watermark = lsn;
        self.events.push(event);
        lsn
    }

    /// Read events starting from `from_lsn` up to `limit` events.
    pub fn read(&self, from_lsn: u64, limit: usize) -> &[MemoryEvent] {
        if from_lsn > self.high_watermark || self.events.is_empty() {
            return &[];
        }
        let start = from_lsn as usize;
        if start >= self.events.len() {
            return &[];
        }
        let end = (start + limit).min(self.events.len());
        &self.events[start..end]
    }

    /// Get the current high watermark (last committed offset).
    pub fn watermark(&self) -> u64 {
        self.high_watermark
    }

    /// Get total event count.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Get event at a specific LSN.
    pub fn get(&self, lsn: u64) -> Option<&MemoryEvent> {
        self.events.get(lsn as usize)
    }

    /// Compact: remove events below `below_lsn` (for retention).
    /// Returns number of events removed.
    pub fn compact(&mut self, below_lsn: u64) -> usize {
        if below_lsn == 0 || self.events.is_empty() {
            return 0;
        }
        let remove_count = (below_lsn as usize).min(self.events.len());
        self.events.drain(..remove_count);
        remove_count
    }
}

// =============================================================================
// CommitLogConfig
// =============================================================================

/// Configuration for a commit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitLogConfig {
    /// Number of partitions.
    pub partition_count: u32,
    /// Maximum events per partition before compaction is recommended.
    pub max_events_per_partition: u64,
    /// Retention period in milliseconds (0 = infinite).
    pub retention_ms: u64,
    /// Maximum inline payload size before requiring Object Fabric reference.
    pub max_inline_bytes: u64,
}

impl Default for CommitLogConfig {
    fn default() -> Self {
        Self {
            partition_count: 1,
            max_events_per_partition: 1_000_000,
            retention_ms: 0,
            max_inline_bytes: PayloadDescriptor::MAX_INLINE_BYTES,
        }
    }
}

impl CommitLogConfig {
    /// Developer mode: single partition, unlimited retention.
    pub fn developer() -> Self {
        Self::default()
    }

    /// Single-server mode: moderate partitions.
    pub fn single_server() -> Self {
        Self {
            partition_count: 4,
            max_events_per_partition: 10_000_000,
            retention_ms: 30 * 24 * 3600 * 1000, // 30 days
            ..Self::default()
        }
    }

    /// Production mode: many partitions.
    pub fn production(partitions: u32) -> Self {
        Self {
            partition_count: partitions,
            max_events_per_partition: 100_000_000,
            retention_ms: 7 * 24 * 3600 * 1000, // 7 days (cold storage handles long-term)
            ..Self::default()
        }
    }
}

// =============================================================================
// CommitLog — append-only log with partitions
// =============================================================================

/// Append-only commit log with partitioned streams.
///
/// This is the in-memory backend for developer mode. Production deployments
/// swap this for a Kafka/Redpanda-backed implementation via `CommitLogBackend`.
#[derive(Debug, Clone)]
pub struct CommitLog {
    pub config: CommitLogConfig,
    partitions: Vec<Partition>,
    /// Total events across all partitions.
    total_events: u64,
}

impl CommitLog {
    pub fn new(config: CommitLogConfig) -> Self {
        let partitions = (0..config.partition_count)
            .map(Partition::new)
            .collect();
        Self {
            config,
            partitions,
            total_events: 0,
        }
    }

    /// Create with default developer config.
    pub fn developer() -> Self {
        Self::new(CommitLogConfig::developer())
    }

    /// Append an event. Partition is selected by hashing the partition_key.
    /// Returns `(partition_id, lsn)`.
    pub fn append(&mut self, event: MemoryEvent) -> (u32, u64) {
        let partition_id = self.partition_for_key(&event.partition_key);
        let lsn = self.partitions[partition_id as usize].append(event);
        self.total_events += 1;
        (partition_id, lsn)
    }

    /// Read events from a specific partition starting at `from_lsn`.
    pub fn read(&self, partition_id: u32, from_lsn: u64, limit: usize) -> &[MemoryEvent] {
        if let Some(partition) = self.partitions.get(partition_id as usize) {
            partition.read(from_lsn, limit)
        } else {
            &[]
        }
    }

    /// Get a specific event by partition and LSN.
    pub fn get(&self, partition_id: u32, lsn: u64) -> Option<&MemoryEvent> {
        self.partitions.get(partition_id as usize)?.get(lsn)
    }

    /// Get the high watermark for a partition.
    pub fn watermark(&self, partition_id: u32) -> Option<u64> {
        self.partitions.get(partition_id as usize).map(|p| p.watermark())
    }

    /// Get total event count across all partitions.
    pub fn total_events(&self) -> u64 {
        self.total_events
    }

    /// Get partition count.
    pub fn partition_count(&self) -> u32 {
        self.config.partition_count
    }

    /// Get the partition for a given key (consistent hashing).
    fn partition_for_key(&self, key: &str) -> u32 {
        if self.config.partition_count <= 1 {
            return 0;
        }
        // FNV-1a hash for fast, well-distributed partition assignment.
        let mut hash: u64 = 0xcbf29ce484222325;
        for byte in key.bytes() {
            hash ^= byte as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
        (hash % self.config.partition_count as u64) as u32
    }

    /// Compact all partitions below a given LSN.
    pub fn compact_all(&mut self, below_lsn: u64) -> usize {
        let mut total = 0;
        for partition in &mut self.partitions {
            total += partition.compact(below_lsn);
        }
        total
    }

    /// Get partition stats.
    pub fn partition_stats(&self) -> Vec<PartitionStats> {
        self.partitions.iter().map(|p| PartitionStats {
            id: p.id,
            event_count: p.len() as u64,
            high_watermark: p.watermark(),
        }).collect()
    }
}

/// Stats for a single partition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartitionStats {
    pub id: u32,
    pub event_count: u64,
    pub high_watermark: u64,
}

// =============================================================================
// Checkpoint — consumer progress tracking
// =============================================================================

/// A materializer's checkpoint: (stream, partition, lsn).
///
/// On restart, a materializer resumes from its last checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub group_id: String,
    pub stream: String,
    pub partition: u32,
    pub lsn: u64,
    pub timestamp: i64,
}

// =============================================================================
// MaterializerGroup — consumer group
// =============================================================================

/// A group of materializers that collectively consume from the commit log.
///
/// Analogous to a Kafka consumer group. Each partition is assigned to exactly
/// one materializer in the group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MaterializerGroup {
    pub group_id: String,
    pub materializer_type: MaterializerType,
    /// Checkpoint per (stream, partition).
    checkpoints: HashMap<(String, u32), u64>,
}

impl MaterializerGroup {
    pub fn new(group_id: String, materializer_type: MaterializerType) -> Self {
        Self {
            group_id,
            materializer_type,
            checkpoints: HashMap::new(),
        }
    }

    /// Get the last committed offset for a (stream, partition).
    pub fn offset(&self, stream: &str, partition: u32) -> u64 {
        self.checkpoints.get(&(stream.to_string(), partition)).copied().unwrap_or(0)
    }

    /// Commit a new offset for a (stream, partition).
    pub fn commit(&mut self, stream: &str, partition: u32, lsn: u64) {
        self.checkpoints.insert((stream.to_string(), partition), lsn);
    }

    /// Get all checkpoints.
    pub fn checkpoints(&self) -> &HashMap<(String, u32), u64> {
        &self.checkpoints
    }

    /// Reset all checkpoints to 0 (for full replay).
    pub fn reset(&mut self) {
        self.checkpoints.clear();
    }
}

// =============================================================================
// CommitLogBackend trait — pluggable backend
// =============================================================================

/// Backend trait for commit log persistence.
///
/// In-memory `CommitLog` implements this directly. Production backends
/// (Kafka, Redpanda, file-backed) implement this trait for swap-in.
pub trait CommitLogBackend: Send + Sync {
    fn append(&mut self, event: MemoryEvent) -> Result<(u32, u64), String>;
    fn read(&self, partition: u32, from_lsn: u64, limit: usize) -> Result<Vec<MemoryEvent>, String>;
    fn watermark(&self, partition: u32) -> Result<u64, String>;
    fn partition_count(&self) -> u32;
}

impl CommitLogBackend for CommitLog {
    fn append(&mut self, event: MemoryEvent) -> Result<(u32, u64), String> {
        Ok(CommitLog::append(self, event))
    }

    fn read(&self, partition: u32, from_lsn: u64, limit: usize) -> Result<Vec<MemoryEvent>, String> {
        Ok(CommitLog::read(self, partition, from_lsn, limit).to_vec())
    }

    fn watermark(&self, partition: u32) -> Result<u64, String> {
        CommitLog::watermark(self, partition).ok_or_else(|| format!("Partition {} not found", partition))
    }

    fn partition_count(&self) -> u32 {
        CommitLog::partition_count(self)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(container: &str, partition_key: &str, event_type: EventType) -> MemoryEvent {
        MemoryEvent {
            event_id: generate_id("evt"),
            tenant_id: "tenant:test".to_string(),
            container_id: container.to_string(),
            trace_id: None,
            partition_key: partition_key.to_string(),
            event_type,
            memory_class: MemoryClass::Episodic,
            producer_id: "pid:001".to_string(),
            idempotency_key: generate_id("idem"),
            payload: PayloadDescriptor::inline("application/json", serde_json::json!({"test": true})),
            policy: PolicySnapshot::default(),
            timestamp: now_ms(),
            lsn: 0,
        }
    }

    #[test]
    fn test_partition_append_and_read() {
        let mut p = Partition::new(0);
        assert!(p.is_empty());

        let evt = make_event("cont:A", "key:1", EventType::InteractionCreated);
        let lsn = p.append(evt);
        assert_eq!(lsn, 0);
        assert_eq!(p.len(), 1);
        assert_eq!(p.watermark(), 0);

        let lsn2 = p.append(make_event("cont:A", "key:2", EventType::ToolOutputProduced));
        assert_eq!(lsn2, 1);
        assert_eq!(p.len(), 2);

        let events = p.read(0, 10);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].lsn, 0);
        assert_eq!(events[1].lsn, 1);

        let events = p.read(1, 10);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].lsn, 1);
    }

    #[test]
    fn test_partition_read_empty() {
        let p = Partition::new(0);
        let events = p.read(0, 10);
        assert!(events.is_empty());
    }

    #[test]
    fn test_partition_read_beyond_watermark() {
        let mut p = Partition::new(0);
        p.append(make_event("cont:A", "key:1", EventType::InteractionCreated));
        let events = p.read(5, 10);
        assert!(events.is_empty());
    }

    #[test]
    fn test_commit_log_single_partition() {
        let mut log = CommitLog::developer();
        assert_eq!(log.partition_count(), 1);
        assert_eq!(log.total_events(), 0);

        let (pid, lsn) = log.append(make_event("cont:A", "key:1", EventType::InteractionCreated));
        assert_eq!(pid, 0);
        assert_eq!(lsn, 0);
        assert_eq!(log.total_events(), 1);

        let events = log.read(0, 0, 100);
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn test_commit_log_multi_partition() {
        let config = CommitLogConfig {
            partition_count: 4,
            ..CommitLogConfig::default()
        };
        let mut log = CommitLog::new(config);

        // Append events with different keys — they should distribute across partitions
        let mut partition_hits = HashMap::new();
        for i in 0..100 {
            let key = format!("agent:pid:{:03}", i);
            let (pid, _) = log.append(make_event("cont:A", &key, EventType::InteractionCreated));
            *partition_hits.entry(pid).or_insert(0u32) += 1;
        }

        assert_eq!(log.total_events(), 100);

        // With 100 keys and 4 partitions, at least 2 partitions should have events
        assert!(partition_hits.len() >= 2, "Events should distribute: {:?}", partition_hits);
    }

    #[test]
    fn test_commit_log_partition_consistency() {
        let config = CommitLogConfig {
            partition_count: 4,
            ..CommitLogConfig::default()
        };
        let mut log = CommitLog::new(config);

        // Same key always goes to same partition
        let (pid1, _) = log.append(make_event("cont:A", "agent:X", EventType::InteractionCreated));
        let (pid2, _) = log.append(make_event("cont:A", "agent:X", EventType::ToolOutputProduced));
        assert_eq!(pid1, pid2, "Same partition key must go to same partition");
    }

    #[test]
    fn test_materializer_group_checkpointing() {
        let mut group = MaterializerGroup::new(
            "vec-materializer".to_string(),
            MaterializerType::Vector,
        );

        assert_eq!(group.offset("stream:A", 0), 0);

        group.commit("stream:A", 0, 42);
        assert_eq!(group.offset("stream:A", 0), 42);

        group.commit("stream:A", 0, 100);
        assert_eq!(group.offset("stream:A", 0), 100);

        // Different stream/partition
        assert_eq!(group.offset("stream:B", 0), 0);
        group.commit("stream:B", 0, 10);
        assert_eq!(group.offset("stream:B", 0), 10);
    }

    #[test]
    fn test_materializer_group_reset() {
        let mut group = MaterializerGroup::new("obj-mat".to_string(), MaterializerType::Object);
        group.commit("s", 0, 50);
        group.commit("s", 1, 30);
        assert_eq!(group.checkpoints().len(), 2);

        group.reset();
        assert_eq!(group.checkpoints().len(), 0);
        assert_eq!(group.offset("s", 0), 0);
    }

    #[test]
    fn test_commit_log_get_event() {
        let mut log = CommitLog::developer();
        let evt = make_event("cont:A", "key:1", EventType::FileUploaded);
        let (pid, lsn) = log.append(evt.clone());

        let fetched = log.get(pid, lsn);
        assert!(fetched.is_some());
        assert_eq!(fetched.unwrap().event_type, EventType::FileUploaded);

        assert!(log.get(pid, 999).is_none());
        assert!(log.get(99, 0).is_none());
    }

    #[test]
    fn test_partition_compact() {
        let mut p = Partition::new(0);
        for i in 0..10 {
            p.append(make_event("cont:A", &format!("k:{}", i), EventType::InteractionCreated));
        }
        assert_eq!(p.len(), 10);

        let removed = p.compact(3);
        assert_eq!(removed, 3);
        assert_eq!(p.len(), 7);
    }

    #[test]
    fn test_commit_log_partition_stats() {
        let mut log = CommitLog::new(CommitLogConfig { partition_count: 2, ..Default::default() });
        for i in 0..20 {
            log.append(make_event("c", &format!("k:{}", i), EventType::InteractionCreated));
        }

        let stats = log.partition_stats();
        assert_eq!(stats.len(), 2);
        let total: u64 = stats.iter().map(|s| s.event_count).sum();
        assert_eq!(total, 20);
    }

    #[test]
    fn test_commit_log_backend_trait() {
        let mut log = CommitLog::developer();
        let backend: &mut dyn CommitLogBackend = &mut log;
        let (pid, lsn) = backend.append(make_event("c", "k", EventType::InteractionCreated)).unwrap();
        let events = backend.read(pid, lsn, 10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(backend.partition_count(), 1);
    }

    #[test]
    fn test_config_presets() {
        let dev = CommitLogConfig::developer();
        assert_eq!(dev.partition_count, 1);
        assert_eq!(dev.retention_ms, 0);

        let ss = CommitLogConfig::single_server();
        assert_eq!(ss.partition_count, 4);
        assert!(ss.retention_ms > 0);

        let prod = CommitLogConfig::production(64);
        assert_eq!(prod.partition_count, 64);
    }
}
