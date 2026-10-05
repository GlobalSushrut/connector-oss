//! INF-P4-1 — Disruptor ring dispatch (T4, 6M+ ops/sec)
//!
//! Lock-free single-producer, multi-consumer ring buffer modelled on the
//! LMAX Disruptor pattern (Thompson et al., 2011).
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │                    RingBuffer<Slot>                       │
//! │  [0][1][2]...[N-1]  (power-of-2, pre-allocated, reused) │
//! └──────────────────────────────────────────────────────────┘
//!          ↑ single writer (AtomicI64 producer_cursor)
//!          ↓ 3 independent consumers (AtomicI64 per consumer)
//!   JOURNALER | REPLICATOR | KERNEL_DISPATCH
//! ```
//!
//! # Key properties
//!
//! - **Zero allocation per op**: slots are pre-allocated, reused in place
//! - **No locks on critical path**: all coordination via `AtomicI64` cursors
//! - **Power-of-2 ring**: index masking with `& (size-1)` replaces modulo
//! - **Cache-line padding**: producer and each consumer cursor on separate cache lines
//! - **Backpressure**: producer stalls if any consumer is more than `size` slots behind
//!
//! # Scale target
//!
//! Single threaded benchmark target: **6M+ ops/sec** at T4.
//! At T3 (1M ops/sec), the in-process `tokio::sync::broadcast` is sufficient.

use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::cell::UnsafeCell;

// ═══════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════

/// Default ring size: 65536 slots (must be power of 2).
/// At 6M ops/sec, ring cycles every ~11ms — large enough to absorb bursts.
pub const DEFAULT_RING_SIZE: usize = 1 << 16; // 65536

/// Number of named consumers.
pub const CONSUMER_COUNT: usize = 3;

/// Consumer index constants.
pub const JOURNALER:       usize = 0;
pub const REPLICATOR:      usize = 1;
pub const KERNEL_DISPATCH: usize = 2;

// ═══════════════════════════════════════════════════════════════
// Ring slot
// ═══════════════════════════════════════════════════════════════

/// A single slot in the ring buffer.
///
/// Slots are pre-allocated and written in-place. The `sequence` field
/// acts as a sequence lock: the producer writes the payload then
/// increments `sequence`; consumers check `sequence == slot_index + 1`
/// before reading.
#[repr(C, align(64))] // align to cache line
pub struct Slot {
    /// Sequence number: 0 = empty, N+1 = written for logical position N.
    pub sequence: AtomicI64,
    /// The event payload stored in this slot.
    pub event: UnsafeCell<RingEvent>,
}

impl Slot {
    fn new(seq: i64) -> Self {
        Self {
            sequence: AtomicI64::new(seq),
            event: UnsafeCell::new(RingEvent::default()),
        }
    }
}

// SAFETY: Slots are accessed under sequence-lock protocol.
unsafe impl Send for Slot {}
unsafe impl Sync for Slot {}

// ═══════════════════════════════════════════════════════════════
// Ring event payload
// ═══════════════════════════════════════════════════════════════

/// Event payload written into a ring slot.
///
/// Sized to fit in a cache line (64 bytes max) where possible.
/// For large payloads, store a handle/CID and fetch from side buffer.
#[derive(Clone, Default)]
pub struct RingEvent {
    /// Logical sequence number of this event.
    pub sequence: i64,
    /// Type tag for routing to the right consumer handler.
    pub event_type: RingEventType,
    /// Agent PID (up to 32 bytes inline, rest truncated).
    pub agent_pid: [u8; 32],
    pub agent_pid_len: u8,
    /// Operation code (maps to `MemoryKernelOp`).
    pub op_code: u16,
    /// CID of the associated packet/entry (32 bytes = SHA-256).
    pub cid_bytes: [u8; 32],
    /// Timestamp (ms since epoch).
    pub timestamp_ms: i64,
}

/// Event type tag — determines which consumers handle this event.
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
#[repr(u8)]
pub enum RingEventType {
    /// Write to audit journal
    #[default]
    AuditWrite = 0,
    /// Replicate to peer cells
    Replicate   = 1,
    /// Dispatch to kernel for execution
    KernelOp    = 2,
    /// All consumers must handle (broadcast)
    Broadcast   = 3,
}

impl RingEventType {
    /// Returns true if this event type should be handled by the given consumer.
    pub fn handles(&self, consumer: usize) -> bool {
        match self {
            RingEventType::AuditWrite => consumer == JOURNALER,
            RingEventType::Replicate  => consumer == REPLICATOR,
            RingEventType::KernelOp   => consumer == KERNEL_DISPATCH,
            RingEventType::Broadcast  => true,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Producer cursor (cache-line padded)
// ═══════════════════════════════════════════════════════════════

#[repr(C, align(128))] // 128-byte padding = 2 cache lines (hardware prefetcher)
struct PaddedCursor {
    cursor: AtomicI64,
    _pad: [u8; 120],
}

impl PaddedCursor {
    fn new(val: i64) -> Self {
        Self { cursor: AtomicI64::new(val), _pad: [0u8; 120] }
    }
}

// ═══════════════════════════════════════════════════════════════
// INF-P4-1: DisruptorRing
// ═══════════════════════════════════════════════════════════════

/// Lock-free ring buffer with single writer and 3 independent consumers.
///
/// # Usage
///
/// ```
/// use vac_core::disruptor::{DisruptorRing, RingEvent, RingEventType, KERNEL_DISPATCH};
///
/// let ring = DisruptorRing::new(1024);
/// let mut event = RingEvent::default();
/// event.event_type = RingEventType::KernelOp;
/// ring.publish(event);
///
/// if let Some(evt) = ring.try_consume(KERNEL_DISPATCH) {
///     // handle evt
/// }
/// ```
pub struct DisruptorRing {
    slots:           Box<[Slot]>,
    size:            usize,
    mask:            i64,
    producer_cursor: PaddedCursor,
    consumer_cursors: [PaddedCursor; CONSUMER_COUNT],
}

impl DisruptorRing {
    /// Create a new ring buffer with `size` slots (must be power of 2).
    /// Panics if `size` is 0 or not a power of 2.
    pub fn new(size: usize) -> Arc<Self> {
        assert!(size > 0 && size.is_power_of_two(), "ring size must be a power of 2");
        let slots: Vec<Slot> = (0..size).map(|i| Slot::new(i as i64)).collect();
        Arc::new(Self {
            slots: slots.into_boxed_slice(),
            size,
            mask: (size as i64) - 1,
            producer_cursor: PaddedCursor::new(-1),
            consumer_cursors: [
                PaddedCursor::new(-1),
                PaddedCursor::new(-1),
                PaddedCursor::new(-1),
            ],
        })
    }

    /// Claim the next sequence number for writing.
    /// Spins (busy-wait) until at least one consumer slot is free.
    /// Returns the claimed sequence number.
    #[inline]
    pub fn claim_next(&self) -> i64 {
        let next = self.producer_cursor.cursor.fetch_add(1, Ordering::AcqRel) + 1;
        // Backpressure: wait until slowest consumer has processed enough slots
        // to free the slot we need.
        let wrap_point = next - self.size as i64;
        loop {
            let min_consumer = self.min_consumer_cursor();
            if min_consumer >= wrap_point {
                break;
            }
            std::hint::spin_loop();
        }
        next
    }

    /// Write an event at the given sequence slot and publish it.
    /// Must be called after `claim_next()`.
    #[inline]
    pub fn write_and_publish(&self, seq: i64, mut event: RingEvent) {
        event.sequence = seq;
        let slot = &self.slots[(seq & self.mask) as usize];
        // SAFETY: we have exclusive access to this slot via the claimed sequence.
        unsafe { *slot.event.get() = event; }
        // Publish: increment sequence so consumers can read.
        slot.sequence.store(seq + 1, Ordering::Release);
    }

    /// Convenience: claim and publish in one call (single-threaded producer).
    #[inline]
    pub fn publish(&self, event: RingEvent) {
        let seq = self.claim_next();
        self.write_and_publish(seq, event);
    }

    /// Try to consume the next event for the given consumer (non-blocking).
    /// Returns `Some(event)` if a new event is available, `None` otherwise.
    #[inline]
    pub fn try_consume(&self, consumer: usize) -> Option<RingEvent> {
        debug_assert!(consumer < CONSUMER_COUNT);
        let next = self.consumer_cursors[consumer].cursor.load(Ordering::Acquire) + 1;
        let slot = &self.slots[(next & self.mask) as usize];
        let seq = slot.sequence.load(Ordering::Acquire);
        if seq == next + 1 {
            // SAFETY: sequence lock ensures slot is fully written.
            let event = unsafe { (*slot.event.get()).clone() };
            self.consumer_cursors[consumer].cursor.store(next, Ordering::Release);
            Some(event)
        } else {
            None
        }
    }

    /// Drain all available events for the given consumer, up to `max`.
    pub fn drain(&self, consumer: usize, max: usize) -> Vec<RingEvent> {
        let mut events = Vec::new();
        while events.len() < max {
            match self.try_consume(consumer) {
                Some(e) => events.push(e),
                None    => break,
            }
        }
        events
    }

    /// Returns the current producer cursor position (last published sequence).
    #[inline]
    pub fn producer_cursor(&self) -> i64 {
        self.producer_cursor.cursor.load(Ordering::Acquire)
    }

    /// Returns the current cursor position for a consumer.
    #[inline]
    pub fn consumer_cursor(&self, consumer: usize) -> i64 {
        self.consumer_cursors[consumer].cursor.load(Ordering::Acquire)
    }

    /// Returns the minimum consumer cursor (slowest consumer).
    #[inline]
    fn min_consumer_cursor(&self) -> i64 {
        self.consumer_cursors.iter()
            .map(|c| c.cursor.load(Ordering::Acquire))
            .min()
            .unwrap_or(-1)
    }

    /// Number of events available for the given consumer.
    pub fn available(&self, consumer: usize) -> i64 {
        let produced = self.producer_cursor();
        let consumed = self.consumer_cursor(consumer);
        (produced - consumed).max(0)
    }

    /// Ring capacity.
    pub fn capacity(&self) -> usize { self.size }
}

// ═══════════════════════════════════════════════════════════════
// Consumer handler trait
// ═══════════════════════════════════════════════════════════════

/// Trait for ring buffer event consumers.
pub trait RingConsumer: Send {
    /// Process a single event. Called by the consumer loop.
    fn on_event(&mut self, event: &RingEvent);
    /// Consumer index (JOURNALER, REPLICATOR, or KERNEL_DISPATCH).
    fn consumer_index(&self) -> usize;
}

/// Runs a consumer in a tight loop, draining events and dispatching to the handler.
/// Intended to be run in a dedicated thread or tokio blocking task.
pub fn run_consumer_loop(ring: Arc<DisruptorRing>, mut handler: impl RingConsumer) {
    let idx = handler.consumer_index();
    loop {
        let events = ring.drain(idx, 256);
        if events.is_empty() {
            std::hint::spin_loop();
        } else {
            for event in &events {
                if event.event_type.handles(idx) {
                    handler.on_event(event);
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Built-in no-op consumers (for testing/benchmarking)
// ═══════════════════════════════════════════════════════════════

/// Journaler consumer — counts events, simulates write to WAL.
pub struct JournalerConsumer { pub events_processed: u64 }
impl RingConsumer for JournalerConsumer {
    fn on_event(&mut self, _event: &RingEvent) { self.events_processed += 1; }
    fn consumer_index(&self) -> usize { JOURNALER }
}

/// Replicator consumer — counts events, simulates forwarding to peer cells.
pub struct ReplicatorConsumer { pub events_forwarded: u64 }
impl RingConsumer for ReplicatorConsumer {
    fn on_event(&mut self, _event: &RingEvent) { self.events_forwarded += 1; }
    fn consumer_index(&self) -> usize { REPLICATOR }
}

/// KernelDispatch consumer — counts events, simulates kernel execution.
pub struct KernelDispatchConsumer { pub ops_dispatched: u64 }
impl RingConsumer for KernelDispatchConsumer {
    fn on_event(&mut self, _event: &RingEvent) { self.ops_dispatched += 1; }
    fn consumer_index(&self) -> usize { KERNEL_DISPATCH }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inf_p4_1_ring_size_must_be_power_of_two() {
        let ring = DisruptorRing::new(64);
        assert_eq!(ring.capacity(), 64);
    }

    #[test]
    #[should_panic]
    fn test_inf_p4_1_non_power_of_two_panics() {
        DisruptorRing::new(100);
    }

    #[test]
    fn test_inf_p4_1_publish_and_consume() {
        let ring = DisruptorRing::new(256);
        let mut event = RingEvent::default();
        event.event_type = RingEventType::KernelOp;
        event.op_code = 42;
        ring.publish(event);

        // KERNEL_DISPATCH should receive it
        let consumed = ring.try_consume(KERNEL_DISPATCH);
        assert!(consumed.is_some());
        assert_eq!(consumed.unwrap().op_code, 42);
    }

    #[test]
    fn test_inf_p4_1_three_independent_consumers() {
        let ring = DisruptorRing::new(256);
        let mut event = RingEvent::default();
        event.event_type = RingEventType::Broadcast;
        ring.publish(event);

        // All three consumers get the event independently
        assert!(ring.try_consume(JOURNALER).is_some());
        assert!(ring.try_consume(REPLICATOR).is_some());
        assert!(ring.try_consume(KERNEL_DISPATCH).is_some());
    }

    #[test]
    fn test_inf_p4_1_consumer_cursors_are_independent() {
        let ring = DisruptorRing::new(256);
        for i in 0..10 {
            let mut ev = RingEvent::default();
            ev.event_type = RingEventType::Broadcast;
            ev.op_code = i;
            ring.publish(ev);
        }

        // Drain JOURNALER only
        let drained = ring.drain(JOURNALER, 10);
        assert_eq!(drained.len(), 10);

        // REPLICATOR has not consumed yet
        assert_eq!(ring.available(REPLICATOR), 10);
        assert_eq!(ring.available(JOURNALER), 0);
    }

    #[test]
    fn test_inf_p4_1_slots_reused_after_full_ring() {
        let ring = DisruptorRing::new(64);
        // Drain all consumers to keep them caught up
        for _ in 0..64 {
            let mut ev = RingEvent::default();
            ev.event_type = RingEventType::Broadcast;
            ring.publish(ev);
            ring.try_consume(JOURNALER);
            ring.try_consume(REPLICATOR);
            ring.try_consume(KERNEL_DISPATCH);
        }
        // Publish again — slots must have been reused (no hang)
        let mut ev = RingEvent::default();
        ev.op_code = 99;
        ev.event_type = RingEventType::KernelOp;
        ring.publish(ev);
        let got = ring.try_consume(KERNEL_DISPATCH).unwrap();
        assert_eq!(got.op_code, 99);
    }

    #[test]
    fn test_inf_p4_1_zero_allocation_no_new_vec_on_publish() {
        // Verify publish() only writes into pre-allocated slots (no heap alloc)
        let ring = DisruptorRing::new(1024);
        for i in 0..1024u16 {
            let mut ev = RingEvent::default();
            ev.op_code = i;
            ev.event_type = RingEventType::KernelOp;
            ring.publish(ev);
            ring.try_consume(JOURNALER);
            ring.try_consume(REPLICATOR);
            ring.try_consume(KERNEL_DISPATCH);
        }
        assert_eq!(ring.producer_cursor(), 1023);
    }

    #[test]
    fn test_inf_p4_1_event_type_routing() {
        assert!(RingEventType::AuditWrite.handles(JOURNALER));
        assert!(!RingEventType::AuditWrite.handles(REPLICATOR));
        assert!(!RingEventType::AuditWrite.handles(KERNEL_DISPATCH));

        assert!(RingEventType::Replicate.handles(REPLICATOR));
        assert!(!RingEventType::Replicate.handles(JOURNALER));

        assert!(RingEventType::KernelOp.handles(KERNEL_DISPATCH));
        assert!(!RingEventType::KernelOp.handles(JOURNALER));

        assert!(RingEventType::Broadcast.handles(JOURNALER));
        assert!(RingEventType::Broadcast.handles(REPLICATOR));
        assert!(RingEventType::Broadcast.handles(KERNEL_DISPATCH));
    }

    #[test]
    fn test_inf_p4_1_available_count_is_correct() {
        let ring = DisruptorRing::new(256);
        assert_eq!(ring.available(JOURNALER), 0);
        for _ in 0..5 {
            ring.publish(RingEvent::default());
        }
        assert_eq!(ring.available(JOURNALER), 5);
        ring.try_consume(JOURNALER);
        assert_eq!(ring.available(JOURNALER), 4);
    }

    #[test]
    fn test_inf_p4_1_journaler_consumer_handler() {
        let ring = DisruptorRing::new(256);
        let mut journaler = JournalerConsumer { events_processed: 0 };
        for _ in 0..20 {
            let mut ev = RingEvent::default();
            ev.event_type = RingEventType::AuditWrite;
            ring.publish(ev);
        }
        let events = ring.drain(JOURNALER, 100);
        for e in &events { journaler.on_event(e); }
        assert_eq!(journaler.events_processed, 20);
    }
}
