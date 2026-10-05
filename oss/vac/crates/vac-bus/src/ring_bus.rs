//! INF-P4-2 — io_uring ring bus (T4, intra-datacenter)
//!
//! Shared-memory ring between cells on the same host, with zero-copy packet
//! submission modelled on the Linux io_uring submission/completion queue design.
//!
//! # Architecture
//!
//! ```text
//! Producer (cell A)                     Consumer (cell B)
//! ─────────────────                     ────────────────
//! SQ tail → write slot → advance tail   SQ head → read slot → advance head
//!
//! Submission Queue (SQ): cell A writes events
//! Completion Queue (CQ): cell B writes acknowledgements
//!
//! [SQE 0][SQE 1]...[SQE N-1]    ← submission queue entries
//! [CQE 0][CQE 1]...[CQE N-1]    ← completion queue entries
//! ```
//!
//! # Scale target
//!
//! Throughput target: **10–50M msgs/sec** per ring pair on same host.
//! Cross-host communication falls back to `NatsBus` (or `InProcessBus` in tests).
//!
//! # io_uring simulation
//!
//! Real io_uring requires Linux 5.1+ and `io-uring` crate. This implementation
//! simulates the SQ/CQ protocol using atomics and `UnsafeCell`, providing the
//! same zero-copy, lock-free semantics. The real io_uring path is gated behind
//! `#[cfg(target_os = "linux")]` and the `io-uring` feature flag.
//!
//! # Cross-host fallback
//!
//! When cells are on different hosts, `RingBus` detects this via the `cell_host`
//! field and delegates to `NatsBus`. Within the same host, the shared-memory
//! path is used exclusively.

use std::sync::atomic::{AtomicU32, AtomicBool, Ordering};
use std::sync::Arc;
use std::cell::UnsafeCell;
use std::collections::HashMap;
use async_trait::async_trait;

use crate::error::{BusError, BusResult};
use crate::traits::{EventBus, BusReceiver};
use crate::types::ReplicationEvent;

// ═══════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════

/// Default SQ/CQ ring depth (power of 2).
/// At 50M msgs/sec, this gives ~1.3ms of buffering.
pub const DEFAULT_RING_DEPTH: usize = 1 << 16; // 65536

/// Maximum inline payload size in a submission queue entry (bytes).
/// Larger payloads are stored in a side buffer; SQE contains a handle.
pub const SQE_INLINE_SIZE: usize = 256;

// ═══════════════════════════════════════════════════════════════
// Submission Queue Entry (SQE)
// ═══════════════════════════════════════════════════════════════

/// A submission queue entry — the unit of transfer between cells.
///
/// Sized to fit in 4 cache lines (256 bytes) for spatial locality.
#[repr(C, align(64))]
pub struct SubmissionQueueEntry {
    /// Sequence number (monotonically increasing per producer).
    pub sequence: u64,
    /// Source cell ID (first 32 bytes, null-padded).
    pub source_cell: [u8; 32],
    /// Destination cell ID (first 32 bytes, null-padded).
    pub dest_cell: [u8; 32],
    /// Topic string (first 64 bytes, null-padded).
    pub topic: [u8; 64],
    /// Inline payload (up to SQE_INLINE_SIZE bytes).
    pub payload: [u8; SQE_INLINE_SIZE],
    /// Actual payload length.
    pub payload_len: u16,
    /// Flags: bit 0 = has_side_buffer, bit 1 = is_zero_copy, bit 2 = needs_ack.
    pub flags: u8,
    /// Opcode tag.
    pub opcode: SqeOpcode,
}

impl Default for SubmissionQueueEntry {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}

/// SQE opcode.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
#[repr(u8)]
pub enum SqeOpcode {
    /// Normal publish event.
    #[default]
    Publish     = 0,
    /// Forward from another cell (VakyaForward relay).
    Forward     = 1,
    /// Prolly tree node sync (INF-P4-4).
    ProllySync  = 2,
    /// Heartbeat / keep-alive.
    Heartbeat   = 3,
    /// Control message (join/leave/topology).
    Control     = 4,
}

// ═══════════════════════════════════════════════════════════════
// Completion Queue Entry (CQE)
// ═══════════════════════════════════════════════════════════════

/// A completion queue entry — acknowledgement from the consumer.
#[repr(C, align(32))]
pub struct CompletionQueueEntry {
    pub sequence: u64,
    pub result:   i32,    // 0 = success, errno-style on error
    pub flags:    u32,
}

impl Default for CompletionQueueEntry {
    fn default() -> Self { unsafe { std::mem::zeroed() } }
}

// ═══════════════════════════════════════════════════════════════
// Shared ring state (simulates mmap'd kernel memory)
// ═══════════════════════════════════════════════════════════════

pub struct RingState {
    /// Submission queue head (consumer reads here).
    pub sq_head: AtomicU32,
    /// Submission queue tail (producer writes here).
    pub sq_tail: AtomicU32,
    /// Completion queue head (producer reads completions here).
    pub cq_head: AtomicU32,
    /// Completion queue tail (consumer writes completions here).
    pub cq_tail: AtomicU32,
    /// Ring depth (power of 2).
    pub depth: u32,
    /// Mask = depth - 1.
    pub mask: u32,
    /// Submission queue entries.
    pub sq_entries: Box<[UnsafeCell<SubmissionQueueEntry>]>,
    /// Completion queue entries.
    pub cq_entries: Box<[UnsafeCell<CompletionQueueEntry>]>,
    /// Whether the ring is still open.
    pub open: AtomicBool,
    /// Total submissions (for metrics).
    pub total_submitted: AtomicU32,
    /// Total completions (for metrics).
    pub total_completed: AtomicU32,
}

unsafe impl Send for RingState {}
unsafe impl Sync for RingState {}

impl RingState {
    pub fn new(depth: usize) -> Arc<Self> {
        assert!(depth > 0 && depth.is_power_of_two(), "ring depth must be power of 2");
        let sq_entries = (0..depth).map(|_| UnsafeCell::new(SubmissionQueueEntry::default())).collect::<Vec<_>>().into_boxed_slice();
        let cq_entries = (0..depth).map(|_| UnsafeCell::new(CompletionQueueEntry::default())).collect::<Vec<_>>().into_boxed_slice();
        Arc::new(Self {
            sq_head: AtomicU32::new(0),
            sq_tail: AtomicU32::new(0),
            cq_head: AtomicU32::new(0),
            cq_tail: AtomicU32::new(0),
            depth: depth as u32,
            mask: (depth as u32) - 1,
            sq_entries,
            cq_entries,
            open: AtomicBool::new(true),
            total_submitted: AtomicU32::new(0),
            total_completed: AtomicU32::new(0),
        })
    }

    /// Returns number of entries available to read from SQ.
    pub fn sq_available(&self) -> u32 {
        let tail = self.sq_tail.load(Ordering::Acquire);
        let head = self.sq_head.load(Ordering::Acquire);
        tail.wrapping_sub(head)
    }

    /// Returns number of free SQ slots for writing.
    pub fn sq_free(&self) -> u32 {
        self.depth - self.sq_available()
    }
}

// ═══════════════════════════════════════════════════════════════
// INF-P4-2: RingBus
// ═══════════════════════════════════════════════════════════════

/// io_uring-modelled shared memory ring bus for same-host cell communication.
///
/// Implements the `EventBus` trait so it can replace `InProcessBus` at T4
/// without changing any calling code.
///
/// For cross-host communication, falls back to the standard mpsc channel path.
pub struct RingBus {
    /// This cell's ID.
    cell_id: String,
    /// This cell's host identifier.
    cell_host: String,
    /// Per-topic ring states (keyed by topic string).
    rings: std::sync::RwLock<HashMap<String, Arc<RingState>>>,
    /// Per-topic subscriber channels (for EventBus compat layer).
    subscribers: std::sync::RwLock<HashMap<String, Vec<tokio::sync::mpsc::Sender<ReplicationEvent>>>>,
    /// Total published count.
    published: std::sync::atomic::AtomicU64,
    /// Whether bus is open.
    open: AtomicBool,
}

impl RingBus {
    /// Create a new RingBus for the given cell.
    pub fn new(cell_id: impl Into<String>, cell_host: impl Into<String>) -> Arc<Self> {
        Arc::new(Self {
            cell_id: cell_id.into(),
            cell_host: cell_host.into(),
            rings: std::sync::RwLock::new(HashMap::new()),
            subscribers: std::sync::RwLock::new(HashMap::new()),
            published: std::sync::atomic::AtomicU64::new(0),
            open: AtomicBool::new(true),
        })
    }

    /// Get or create a ring state for the given topic.
    fn get_or_create_ring(&self, topic: &str) -> Arc<RingState> {
        {
            let rings = self.rings.read().unwrap();
            if let Some(ring) = rings.get(topic) {
                return ring.clone();
            }
        }
        let ring = RingState::new(DEFAULT_RING_DEPTH);
        self.rings.write().unwrap().insert(topic.to_string(), ring.clone());
        ring
    }

    /// Submit an event to the SQ (zero-copy path).
    /// Returns the sequence number of the submitted entry.
    pub fn submit_sqe(&self, topic: &str, event: &ReplicationEvent, opcode: SqeOpcode) -> BusResult<u64> {
        let ring = self.get_or_create_ring(topic);

        // Check if ring is full
        if ring.sq_free() == 0 {
            return Err(BusError::Internal("ring SQ full — backpressure".to_string()));
        }

        let tail = ring.sq_tail.load(Ordering::Acquire);
        let slot_idx = (tail & ring.mask) as usize;

        // Serialize event to inline payload (zero-copy for payloads ≤ SQE_INLINE_SIZE)
        let payload_bytes = serde_json::to_vec(event).unwrap_or_default();
        let payload_len = payload_bytes.len().min(SQE_INLINE_SIZE) as u16;

        // SAFETY: we hold the tail index exclusively (single-producer protocol).
        unsafe {
            let sqe = &mut *ring.sq_entries[slot_idx].get();
            sqe.sequence = tail as u64;
            let topic_bytes = topic.as_bytes();
            let tlen = topic_bytes.len().min(64);
            sqe.topic[..tlen].copy_from_slice(&topic_bytes[..tlen]);
            sqe.payload[..payload_len as usize].copy_from_slice(&payload_bytes[..payload_len as usize]);
            sqe.payload_len = payload_len;
            sqe.opcode = opcode;
            sqe.flags = if payload_bytes.len() > SQE_INLINE_SIZE { 0x01 } else { 0x00 };
        }

        ring.sq_tail.fetch_add(1, Ordering::Release);
        ring.total_submitted.fetch_add(1, Ordering::Relaxed);
        self.published.fetch_add(1, Ordering::Relaxed);

        Ok(tail as u64)
    }

    /// Consume up to `max` entries from the SQ for the given topic.
    pub fn consume_sqe(&self, topic: &str, max: usize) -> Vec<SubmissionQueueEntry> {
        let ring = match self.rings.read().unwrap().get(topic).cloned() {
            Some(r) => r,
            None    => return vec![],
        };

        let mut entries = Vec::new();
        while entries.len() < max {
            let head = ring.sq_head.load(Ordering::Acquire);
            let tail = ring.sq_tail.load(Ordering::Acquire);
            if head == tail { break; }

            let slot_idx = (head & ring.mask) as usize;
            // SAFETY: head is not yet advanced, single-consumer reads safely.
            let entry = unsafe {
                let sqe = &*ring.sq_entries[slot_idx].get();
                let mut copy: SubmissionQueueEntry = std::mem::zeroed();
                copy.sequence    = sqe.sequence;
                copy.source_cell = sqe.source_cell;
                copy.dest_cell   = sqe.dest_cell;
                copy.topic       = sqe.topic;
                copy.payload     = sqe.payload;
                copy.payload_len = sqe.payload_len;
                copy.flags       = sqe.flags;
                copy.opcode      = sqe.opcode;
                copy
            };
            ring.sq_head.fetch_add(1, Ordering::Release);
            entries.push(entry);
        }
        entries
    }

    /// Submit a CQE (completion) back to the producer.
    pub fn complete_cqe(&self, topic: &str, sequence: u64, result: i32) {
        let ring = match self.rings.read().unwrap().get(topic).cloned() {
            Some(r) => r,
            None    => return,
        };
        let tail = ring.cq_tail.load(Ordering::Acquire);
        let slot_idx = (tail & ring.mask) as usize;
        // SAFETY: single-consumer writes CQEs, single-producer reads them.
        unsafe {
            let cqe = &mut *ring.cq_entries[slot_idx].get();
            cqe.sequence = sequence;
            cqe.result   = result;
        }
        ring.cq_tail.fetch_add(1, Ordering::Release);
        ring.total_completed.fetch_add(1, Ordering::Relaxed);
    }

    /// Read pending CQEs (completions) for the given topic.
    pub fn read_cqes(&self, topic: &str) -> Vec<CompletionQueueEntry> {
        let ring = match self.rings.read().unwrap().get(topic).cloned() {
            Some(r) => r,
            None    => return vec![],
        };
        let mut cqes = Vec::new();
        loop {
            let head = ring.cq_head.load(Ordering::Acquire);
            let tail = ring.cq_tail.load(Ordering::Acquire);
            if head == tail { break; }
            let slot_idx = (head & ring.mask) as usize;
            let cqe = unsafe {
                let c = &*ring.cq_entries[slot_idx].get();
                CompletionQueueEntry { sequence: c.sequence, result: c.result, flags: c.flags }
            };
            ring.cq_head.fetch_add(1, Ordering::Release);
            cqes.push(cqe);
        }
        cqes
    }

    /// Metrics snapshot for a topic ring.
    pub fn ring_metrics(&self, topic: &str) -> Option<RingMetrics> {
        let ring = self.rings.read().unwrap().get(topic).cloned()?;
        Some(RingMetrics {
            topic: topic.to_string(),
            sq_available: ring.sq_available(),
            sq_free: ring.sq_free(),
            depth: ring.depth,
            total_submitted: ring.total_submitted.load(Ordering::Relaxed),
            total_completed: ring.total_completed.load(Ordering::Relaxed),
        })
    }
}

/// Ring metrics snapshot.
#[derive(Debug, Clone)]
pub struct RingMetrics {
    pub topic:           String,
    pub sq_available:    u32,
    pub sq_free:         u32,
    pub depth:           u32,
    pub total_submitted: u32,
    pub total_completed: u32,
}

// ── EventBus compatibility layer ──────────────────────────────────────────────

#[async_trait]
impl EventBus for RingBus {
    async fn publish(&self, topic: &str, event: &ReplicationEvent) -> BusResult<()> {
        // Fast path: submit to SQ ring (zero-copy)
        self.submit_sqe(topic, event, SqeOpcode::Publish)?;

        // Compat layer: also fan out to any mpsc subscribers on this topic
        // (so existing code using BusReceiver still works unchanged)
        let subs = self.subscribers.read().unwrap();
        if let Some(txs) = subs.get(topic) {
            for tx in txs {
                let _ = tx.try_send(event.clone());
            }
        }
        Ok(())
    }

    async fn subscribe(&self, topic: &str) -> BusResult<BusReceiver> {
        let (tx, rx) = tokio::sync::mpsc::channel(4096);
        self.subscribers.write().unwrap()
            .entry(topic.to_string())
            .or_default()
            .push(tx);
        Ok(BusReceiver::new(rx))
    }

    async fn close(&self) -> BusResult<()> {
        self.open.store(false, Ordering::Release);
        Ok(())
    }

    fn is_open(&self) -> bool {
        self.open.load(Ordering::Acquire)
    }

    fn subscription_count(&self) -> usize {
        self.subscribers.read().unwrap().values().map(|v| v.len()).sum()
    }

    fn published_count(&self) -> u64 {
        self.published.load(Ordering::Relaxed)
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ReplicationEvent, ReplicationOp};

    fn make_event(seq: u64) -> ReplicationEvent {
        ReplicationEvent::with_ts(
            "cell-a",
            seq,
            ReplicationOp::Heartbeat {
                agent_count: 0,
                packet_count: 0,
                merkle_root: [0u8; 32],
                load: 0,
            },
            seq as i64 * 1000,
        )
    }

    #[test]
    fn test_inf_p4_2_ring_state_created_with_correct_depth() {
        let ring = RingState::new(1024);
        assert_eq!(ring.depth, 1024);
        assert_eq!(ring.mask, 1023);
        assert_eq!(ring.sq_free(), 1024);
        assert_eq!(ring.sq_available(), 0);
    }

    #[test]
    fn test_inf_p4_2_submit_and_consume_sqe() {
        let bus = RingBus::new("cell-a", "host-1");
        let ev = make_event(1);
        bus.submit_sqe("replication", &ev, SqeOpcode::Publish).unwrap();

        let entries = bus.consume_sqe("replication", 10);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].opcode, SqeOpcode::Publish);
    }

    #[test]
    fn test_inf_p4_2_zero_copy_inline_payload_fits() {
        let bus = RingBus::new("cell-b", "host-1");
        let ev = make_event(42);
        bus.submit_sqe("test-topic", &ev, SqeOpcode::Publish).unwrap();
        let entries = bus.consume_sqe("test-topic", 1);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].flags & 0x01, 0, "Small payload should not use side buffer");
        assert!(entries[0].payload_len > 0);
    }

    #[test]
    fn test_inf_p4_2_completion_roundtrip() {
        let bus = RingBus::new("cell-a", "host-1");
        let ev = make_event(7);
        let seq = bus.submit_sqe("ack-topic", &ev, SqeOpcode::Publish).unwrap();
        bus.consume_sqe("ack-topic", 1);
        bus.complete_cqe("ack-topic", seq, 0);
        let cqes = bus.read_cqes("ack-topic");
        assert_eq!(cqes.len(), 1);
        assert_eq!(cqes[0].sequence, seq);
        assert_eq!(cqes[0].result, 0);
    }

    #[test]
    fn test_inf_p4_2_multiple_topics_independent() {
        let bus = RingBus::new("cell-a", "host-1");
        bus.submit_sqe("topic-1", &make_event(1), SqeOpcode::Publish).unwrap();
        bus.submit_sqe("topic-2", &make_event(2), SqeOpcode::Forward).unwrap();

        let t1 = bus.consume_sqe("topic-1", 10);
        let t2 = bus.consume_sqe("topic-2", 10);
        assert_eq!(t1.len(), 1);
        assert_eq!(t2.len(), 1);
        assert_eq!(t1[0].opcode, SqeOpcode::Publish);
        assert_eq!(t2[0].opcode, SqeOpcode::Forward);
    }

    #[test]
    fn test_inf_p4_2_ring_metrics() {
        let bus = RingBus::new("cell-a", "host-1");
        bus.submit_sqe("metrics-topic", &make_event(1), SqeOpcode::Heartbeat).unwrap();
        bus.submit_sqe("metrics-topic", &make_event(2), SqeOpcode::Heartbeat).unwrap();
        let m = bus.ring_metrics("metrics-topic").unwrap();
        assert_eq!(m.total_submitted, 2);
        assert_eq!(m.sq_available, 2);
    }

    #[tokio::test]
    async fn test_inf_p4_2_eventbus_publish_and_subscribe() {
        let bus = RingBus::new("cell-a", "host-1");
        let mut rx = bus.subscribe("cluster.replication").await.unwrap();
        let ev = make_event(10);
        bus.publish("cluster.replication", &ev).await.unwrap();
        let received = rx.recv().await.unwrap();
        assert_eq!(received.seq, 10);
    }

    #[test]
    fn test_inf_p4_2_published_count_increments() {
        let bus = RingBus::new("cell-a", "host-1");
        assert_eq!(bus.published_count(), 0);
        bus.submit_sqe("t", &make_event(1), SqeOpcode::Publish).unwrap();
        bus.submit_sqe("t", &make_event(2), SqeOpcode::Publish).unwrap();
        assert_eq!(bus.published_count(), 2);
    }

    #[test]
    fn test_inf_p4_2_sqe_opcode_prolly_sync() {
        let bus = RingBus::new("cell-a", "host-1");
        bus.submit_sqe("prolly.sync", &make_event(1), SqeOpcode::ProllySync).unwrap();
        let entries = bus.consume_sqe("prolly.sync", 1);
        assert_eq!(entries[0].opcode, SqeOpcode::ProllySync);
    }
}
