# Audit Chain

> KernelAuditEntry, HMAC chain, integrity check, overflow
> Source: `vac/crates/vac-core/src/kernel.rs`, `vac/crates/vac-core/src/store.rs`

---

## KernelAuditEntry

Every `MemoryKernel::dispatch()` call produces exactly one `KernelAuditEntry`:

```rust
pub struct KernelAuditEntry {
    pub audit_id:    String,          // "audit:000017" (zero-padded counter)
    pub agent_pid:   String,          // "pid:000001" or "system"
    pub operation:   String,          // "MemWrite", "AccessGrant", etc.
    pub outcome:     OpOutcome,       // Success | Denied | Failed
    pub timestamp:   i64,             // Unix milliseconds
    pub duration_us: u64,             // operation duration in microseconds
    pub target_cid:  Option<String>,  // CID of affected packet (if any)
    pub reason:      Option<String>,  // human-readable reason
    pub vakya_id:    Option<String>,  // AAPI authorization token ID
}
```

---

## HMAC Chain

Each entry is linked to the previous via HMAC-SHA256:

```
hmac[0] = HMAC-SHA256(key, [0u8; 32] || serialize(entry[0]))
hmac[i] = HMAC-SHA256(key, hmac[i-1] || serialize(entry[i]))
```

**API**:
```rust
// Sign a new entry (appending to chain)
pub fn sign_audit_entry(
    entry:     &KernelAuditEntry,
    key:       &[u8; 32],
    prev_hmac: &[u8; 32],
) -> [u8; 32]

// Verify the full chain
pub fn verify_audit_chain(
    entries: &[KernelAuditEntry],
    key:     &[u8; 32],
    hmacs:   &[[u8; 32]],
) -> Vec<(usize, String)>
// Returns: list of (index, error_message) for any broken links
// Empty vec = chain is intact
```

**What it detects**:

| Attack | Detection |
|--------|-----------|
| Modify entry content | HMAC mismatch at that index |
| Delete an entry | All subsequent HMACs break |
| Insert a fake entry | Chain breaks at insertion point |
| Reorder entries | Chain breaks at first reordering |

---

## Audit Log Bounds

```rust
pub struct MemoryKernel {
    audit_log:            Vec<KernelAuditEntry>,  // active ring buffer
    audit_log_max:        usize,                  // default: 100_000
    audit_overflow:       Vec<KernelAuditEntry>,  // evicted entries
    audit_overflow_count: u64,                    // total evicted
    audit_chain_hash:     Option<String>,         // HMAC of most recent entry
}
```

When `audit_log.len() == audit_log_max`, the oldest entry is moved to `audit_overflow` before the new entry is appended. `audit_overflow` entries are flushed to persistent store by `CheckpointManager`.

---

## Accessing the Audit Trail

Via `KernelOps` (connector-engine):

```rust
pub struct AuditEntry {
    pub audit_id:   String,
    pub timestamp:  i64,
    pub operation:  String,
    pub agent_pid:  String,
    pub outcome:    String,   // "Success" | "Denied" | "Failed"
    pub duration_us: u64,
    pub target_cid: Option<String>,
    pub reason:     Option<String>,
}

// Get last N entries
kernel_ops.audit_tail(n: usize) -> Vec<AuditEntry>

// Get total count
kernel_ops.audit_count() -> usize
```

Via Python SDK (`vac-ffi`):
```python
c.audit_tail(10)   # last 10 entries
c.audit_count()    # total entries
c.integrity_check() # (bool, usize) — ok + error count
```

---

## Integrity Check

`SyscallPayload::IntegrityCheck` verifies:

1. **CID integrity**: For every packet in `packets` HashMap, recompute CID from content and compare. Any mismatch = tampered.
2. **session_index consistency**: All CIDs in `session_index` must exist in `packets`.
3. **Duplicate detection**: No duplicate CIDs in `namespace_index`.

Returns `SyscallValue::Bool(true)` if all checks pass, `Bool(false)` otherwise.

**Note**: `integrity_check()` registers a temporary system agent if no agents are present. Call it **before** terminating agents to get an accurate result.

---

## Audit Export

```rust
// connector-engine/src/kernel_ops.rs
pub struct ExportData {
    pub stats:      KernelStats,
    pub agents:     Vec<AgentInfo>,
    pub sessions:   Vec<SessionInfo>,
    pub namespaces: Vec<NamespaceInfo>,
    pub audit_tail: Vec<AuditEntry>,
}

// Export as pretty JSON
kernel_ops.export_json(audit_tail_limit: usize) -> String

// Access stats
let snap: serde_json::Value = serde_json::from_str(&export_json).unwrap();
let stats = snap["stats"].as_object().unwrap();
// stats["total_agents"], stats["total_packets"], stats["total_audit_entries"]
// stats["total_sessions"], stats["active_agents"], stats["namespaces"]
```

---

## Audit in Practice

```
Demo output from 01_hello_world.py:

[5] last 3 audit ops:
    [Success ] MemWrite              187µs
    [Success ] MemWrite              232µs
    [Denied  ] MemRead               74µs

kernel_stats: {
  'total_packets': 12,
  'total_sessions': 0,
  'total_audit_entries': 22,
  'total_agents': 4,
  'active_sessions': 0,
  'namespaces': 4,
  'active_agents': 4
}
```

The `Denied` entry shows bob's attempt to read alice's CID — logged even though it was rejected.
