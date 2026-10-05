//! Cluster Replication WAL — durability for cross-cell replication.
//!
//! I8 fix (infra.md §13 P1, Gap 5): Without a WAL, a replication op that is
//! in-flight when the process crashes is permanently lost. The WAL guarantees
//! every write is persisted before it is applied locally or published to the bus.
//!
//! ## Write path (ordered steps)
//! 1. `append(op)` — serialize, CRC32, write to WAL, fsync
//! 2. Apply to local KernelStore
//! 3. Publish to replication bus
//! 4. `ack(lsn)` — mark applied; entries ≤ ack_lsn are eligible for compaction
//!
//! ## Recovery path (on restart)
//! - Call `unacked_entries()` → re-apply to store + bus in LSN order
//!
//! ## Group commit
//! - Batch up to `MAX_BATCH_SIZE` (100) entries per fsync
//! - Caller triggers `flush()` periodically (every ~5ms) or when batch is full
//!
//! ## Relationship to `vac_core::range_window::WalEntry`
//! That type tracks uncommitted *packet CIDs* within a single RangeWindow accumulator.
//! This `ReplicationWalEntry` tracks *cluster replication ops* across cells.
//! They are completely independent.

use std::collections::VecDeque;

use serde::{Deserialize, Serialize};

use vac_bus::ReplicationOp;

/// Maximum entries batched before an automatic fsync is forced.
const MAX_BATCH_SIZE: usize = 100;

/// Log Sequence Number — monotonically increasing per cell, never reused.
pub type Lsn = u64;

/// A single cluster replication WAL entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplicationWalEntry {
    /// Monotonically increasing sequence number.
    pub lsn: Lsn,
    /// Cell that originated this entry.
    pub cell_id: String,
    /// The replication operation to persist.
    pub op: ReplicationOp,
    /// CRC32 of `serde_json::to_vec(&op)` — tamper/corruption detection.
    pub crc32: u32,
    /// Milliseconds since Unix epoch.
    pub ts: i64,
}

impl ReplicationWalEntry {
    pub fn new(lsn: Lsn, cell_id: String, op: ReplicationOp) -> Self {
        let op_bytes = serde_json::to_vec(&op).unwrap_or_default();
        let crc32 = crc32_of(&op_bytes);
        Self {
            lsn,
            cell_id,
            op,
            crc32,
            ts: chrono::Utc::now().timestamp_millis(),
        }
    }

    /// Returns `true` if the stored CRC32 matches the serialized op.
    pub fn verify_integrity(&self) -> bool {
        let op_bytes = serde_json::to_vec(&self.op).unwrap_or_default();
        crc32_of(&op_bytes) == self.crc32
    }
}

/// WAL error type.
#[derive(Debug)]
pub enum WalError {
    Serialization(String),
    CrcMismatch { lsn: Lsn, expected: u32, actual: u32 },
}

impl std::fmt::Display for WalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalError::Serialization(s) => write!(f, "WAL serialization error: {}", s),
            WalError::CrcMismatch { lsn, expected, actual } =>
                write!(f, "WAL CRC mismatch at LSN {}: expected {}, got {}", lsn, expected, actual),
        }
    }
}

impl std::error::Error for WalError {}

pub type WalResult<T> = Result<T, WalError>;

// =============================================================================
// InMemoryWal — used for T0/T1 and in tests
// =============================================================================

/// In-memory WAL. No disk I/O — suitable for T0/T1 deployments and unit tests.
///
/// For T2+ (multi-cell) use `DiskWal` which wraps this with fsync semantics.
pub struct InMemoryWal {
    entries: VecDeque<ReplicationWalEntry>,
    /// Pending entries not yet flushed (batch accumulator).
    pending: Vec<ReplicationWalEntry>,
    next_lsn: Lsn,
    last_acked_lsn: Lsn,
    cell_id: String,
}

impl InMemoryWal {
    pub fn new(cell_id: impl Into<String>) -> Self {
        Self {
            entries: VecDeque::new(),
            pending: Vec::new(),
            next_lsn: 1,
            last_acked_lsn: 0,
            cell_id: cell_id.into(),
        }
    }

    /// Append an op. Returns the assigned LSN.
    pub fn append(&mut self, op: ReplicationOp) -> WalResult<Lsn> {
        let lsn = self.next_lsn;
        self.next_lsn += 1;
        let entry = ReplicationWalEntry::new(lsn, self.cell_id.clone(), op);
        self.entries.push_back(entry.clone());
        self.pending.push(entry);
        Ok(lsn)
    }

    /// Flush pending entries (no-op for in-memory; `DiskWal` fsyncs here).
    /// Returns the number of entries flushed.
    pub fn flush(&mut self) -> WalResult<usize> {
        let n = self.pending.len();
        self.pending.clear();
        Ok(n)
    }

    /// Returns `true` if the pending batch is full (should trigger a flush).
    pub fn batch_full(&self) -> bool {
        self.pending.len() >= MAX_BATCH_SIZE
    }

    /// Mark all entries with LSN ≤ `lsn` as applied (safe to compact).
    pub fn ack(&mut self, lsn: Lsn) {
        self.last_acked_lsn = self.last_acked_lsn.max(lsn);
    }

    /// All entries with LSN > `last_acked_lsn` — the recovery set.
    pub fn unacked_entries(&self) -> Vec<ReplicationWalEntry> {
        self.entries.iter()
            .filter(|e| e.lsn > self.last_acked_lsn)
            .cloned()
            .collect()
    }

    /// Drop all entries with LSN ≤ `last_acked_lsn` to reclaim memory.
    pub fn compact(&mut self) {
        self.entries.retain(|e| e.lsn > self.last_acked_lsn);
    }

    // ── Metrics exposed as Prometheus gauges ──

    /// Current highest LSN written.
    pub fn current_lsn(&self) -> Lsn {
        self.next_lsn.saturating_sub(1)
    }

    /// Last LSN acknowledged as applied.
    pub fn last_acked_lsn(&self) -> Lsn {
        self.last_acked_lsn
    }

    /// Replication lag = `current_lsn - last_acked_lsn`.
    /// Alert if this exceeds 10_000 (infra.md §13 observability).
    pub fn lag(&self) -> u64 {
        self.current_lsn().saturating_sub(self.last_acked_lsn)
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn cell_id(&self) -> &str {
        &self.cell_id
    }
}

impl Default for InMemoryWal {
    fn default() -> Self {
        Self::new("default")
    }
}

// =============================================================================
// DiskWal — T2+ deployments (wraps InMemoryWal + disk fsync)
// =============================================================================

/// Disk-backed WAL for T2+ multi-cell deployments.
///
/// Format: newline-delimited JSON (NDJSON), one `ReplicationWalEntry` per line.
/// On open: replays all un-acked entries from disk into the in-memory index.
/// On `flush_to_disk()`: appends pending batch and calls `sync_all()`.
pub struct DiskWal {
    path: std::path::PathBuf,
    inner: InMemoryWal,
}

impl DiskWal {
    /// Open or create a WAL file at `path`.
    /// If the file exists, replays all entries to rebuild the in-memory index.
    pub fn open(
        path: impl AsRef<std::path::Path>,
        cell_id: impl Into<String>,
    ) -> WalResult<Self> {
        let path = path.as_ref().to_path_buf();
        let cell_id = cell_id.into();
        let mut inner = InMemoryWal::new(&cell_id);

        // Replay existing entries on open (recovery path)
        if path.exists() {
            let content = std::fs::read_to_string(&path)
                .map_err(|e| WalError::Serialization(e.to_string()))?;

            let mut recovered = 0usize;
            let mut corrupted = 0usize;

            for line in content.lines() {
                if line.trim().is_empty() {
                    continue;
                }
                match serde_json::from_str::<ReplicationWalEntry>(line) {
                    Ok(entry) => {
                        if !entry.verify_integrity() {
                            corrupted += 1;
                            tracing::warn!(
                                lsn = entry.lsn,
                                cell = %entry.cell_id,
                                "WAL entry CRC mismatch — skipping corrupted entry"
                            );
                            continue;
                        }
                        // Advance next_lsn past the highest replayed LSN
                        if entry.lsn >= inner.next_lsn {
                            inner.next_lsn = entry.lsn + 1;
                        }
                        inner.entries.push_back(entry);
                        recovered += 1;
                    }
                    Err(e) => {
                        corrupted += 1;
                        tracing::warn!(error = %e, "WAL: skipping undeserializable line");
                    }
                }
            }

            tracing::info!(
                path = %path.display(),
                recovered,
                corrupted,
                next_lsn = inner.next_lsn,
                "WAL replayed"
            );
        }

        Ok(Self { path, inner })
    }

    /// Append an op to the WAL. Triggers `flush_to_disk` when batch is full.
    pub fn append(&mut self, op: ReplicationOp) -> WalResult<Lsn> {
        let lsn = self.inner.append(op)?;
        if self.inner.batch_full() {
            self.flush_to_disk()?;
        }
        Ok(lsn)
    }

    /// Force-flush pending batch to disk with fsync.
    /// Call every ~5ms for low-latency durability.
    pub fn flush_to_disk(&mut self) -> WalResult<usize> {
        use std::io::Write;

        if self.inner.pending.is_empty() {
            return Ok(0);
        }

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| WalError::Serialization(e.to_string()))?;

        let n = self.inner.pending.len();
        for entry in &self.inner.pending {
            let line = serde_json::to_string(entry)
                .map_err(|e| WalError::Serialization(e.to_string()))?;
            file.write_all(line.as_bytes())
                .map_err(|e| WalError::Serialization(e.to_string()))?;
            file.write_all(b"\n")
                .map_err(|e| WalError::Serialization(e.to_string()))?;
        }

        // fsync — guarantees durability even on power loss
        file.flush().map_err(|e| WalError::Serialization(e.to_string()))?;
        file.sync_all().map_err(|e| WalError::Serialization(e.to_string()))?;

        self.inner.pending.clear();
        Ok(n)
    }

    /// Ack entries up to `lsn` as applied.
    pub fn ack(&mut self, lsn: Lsn) {
        self.inner.ack(lsn);
    }

    /// All entries not yet acked — replay these on restart.
    pub fn unacked_entries(&self) -> Vec<ReplicationWalEntry> {
        self.inner.unacked_entries()
    }

    /// Drop entries ≤ `last_acked_lsn` from in-memory index.
    pub fn compact(&mut self) {
        self.inner.compact();
    }

    pub fn current_lsn(&self) -> Lsn { self.inner.current_lsn() }
    pub fn last_acked_lsn(&self) -> Lsn { self.inner.last_acked_lsn() }
    /// Lag metric — export as `vac_wal_lag_lsn` in Prometheus.
    pub fn lag(&self) -> u64 { self.inner.lag() }
    pub fn cell_id(&self) -> &str { self.inner.cell_id() }
}

// =============================================================================
// CRC32 — pure Rust, no external dep
// =============================================================================

/// CRC32 (ISO 3309 / ITU-T V.42) of `data`.
fn crc32_of(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= (byte as u32) << 24;
        for _ in 0..8 {
            if crc & 0x8000_0000 != 0 {
                crc = (crc << 1) ^ 0x04C1_1DB7;
            } else {
                crc <<= 1;
            }
        }
    }
    !crc
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use vac_bus::ReplicationOp;

    fn packet_op(ns: &str) -> ReplicationOp {
        ReplicationOp::PacketWrite {
            namespace: ns.to_string(),
            packet_cbor: vec![1, 2, 3],
            packet_cid: "bafytest".to_string(),
        }
    }

    #[test]
    fn test_append_and_lsn_monotonic() {
        let mut wal = InMemoryWal::new("cell-1");
        let l1 = wal.append(packet_op("ns:a")).unwrap();
        let l2 = wal.append(packet_op("ns:b")).unwrap();
        let l3 = wal.append(packet_op("ns:c")).unwrap();
        assert_eq!(l1, 1);
        assert_eq!(l2, 2);
        assert_eq!(l3, 3);
        assert_eq!(wal.current_lsn(), 3);
    }

    #[test]
    fn test_ack_and_lag() {
        let mut wal = InMemoryWal::new("cell-1");
        wal.append(packet_op("ns:a")).unwrap();
        wal.append(packet_op("ns:b")).unwrap();
        wal.append(packet_op("ns:c")).unwrap();

        assert_eq!(wal.lag(), 3);
        wal.ack(2);
        assert_eq!(wal.lag(), 1);
        wal.ack(3);
        assert_eq!(wal.lag(), 0);
    }

    #[test]
    fn test_unacked_entries_after_ack() {
        let mut wal = InMemoryWal::new("cell-1");
        wal.append(packet_op("ns:a")).unwrap();
        wal.append(packet_op("ns:b")).unwrap();
        wal.append(packet_op("ns:c")).unwrap();

        wal.ack(2);
        let unacked = wal.unacked_entries();
        assert_eq!(unacked.len(), 1);
        assert_eq!(unacked[0].lsn, 3);
    }

    #[test]
    fn test_compact_drops_acked() {
        let mut wal = InMemoryWal::new("cell-1");
        for _ in 0..5 {
            wal.append(packet_op("ns:test")).unwrap();
        }
        wal.ack(3);
        wal.compact();
        assert_eq!(wal.entry_count(), 2); // only LSNs 4 and 5 remain
    }

    #[test]
    fn test_crc32_integrity() {
        let op = packet_op("ns:test");
        let entry = ReplicationWalEntry::new(1, "cell-1".to_string(), op);
        assert!(entry.verify_integrity());
    }

    #[test]
    fn test_batch_full_trigger() {
        let mut wal = InMemoryWal::new("cell-1");
        for _ in 0..99 {
            wal.append(packet_op("ns:batch")).unwrap();
        }
        assert!(!wal.batch_full());
        wal.append(packet_op("ns:batch")).unwrap(); // 100th
        assert!(wal.batch_full());
    }

    #[test]
    fn test_flush_clears_pending() {
        let mut wal = InMemoryWal::new("cell-1");
        wal.append(packet_op("ns:a")).unwrap();
        wal.append(packet_op("ns:b")).unwrap();
        assert_eq!(wal.pending_count(), 2);
        let flushed = wal.flush().unwrap();
        assert_eq!(flushed, 2);
        assert_eq!(wal.pending_count(), 0);
        // entries still in main log for recovery
        assert_eq!(wal.entry_count(), 2);
    }

    #[test]
    fn test_disk_wal_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.wal");

        // Write
        {
            let mut wal = DiskWal::open(&path, "cell-disk").unwrap();
            wal.append(packet_op("ns:a")).unwrap();
            wal.append(packet_op("ns:b")).unwrap();
            wal.ack(1);
            wal.flush_to_disk().unwrap();
        }

        // Reopen — should replay both entries, last_acked=0 (not persisted)
        {
            let wal = DiskWal::open(&path, "cell-disk").unwrap();
            assert_eq!(wal.current_lsn(), 2);
            // All entries recovered (ack state is not persisted — caller must re-ack)
            assert_eq!(wal.unacked_entries().len(), 2);
        }
    }

    #[test]
    fn test_disk_wal_lag_metric() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("lag.wal");
        let mut wal = DiskWal::open(&path, "cell-lag").unwrap();
        wal.append(packet_op("ns:a")).unwrap();
        wal.append(packet_op("ns:b")).unwrap();
        wal.flush_to_disk().unwrap();
        assert_eq!(wal.lag(), 2); // nothing acked yet
        wal.ack(2);
        assert_eq!(wal.lag(), 0);
    }
}
