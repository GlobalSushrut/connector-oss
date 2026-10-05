//! Kernel durability metrics for operator surfaces (I-03 partial).

use serde_json::{json, Value};

use crate::state::{KernelDurabilityTracker, SharedState};

pub fn flush_interval_secs() -> u64 {
    std::env::var("CONNECTOR_FLUSH_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(60)
}

/// Live snapshot from Ring-0 kernel + flush tracker.
pub fn durability_snapshot(state: &SharedState) -> Value {
    let (
        packet_count,
        agent_count,
        audit_pending,
        audit_overflow_pending,
        audit_overflow_total,
        chain_ok,
    ) = {
        let k = state.kernel.lock().unwrap();
        (
            k.packet_count(),
            k.agent_count(),
            k.audit_batch_pending(),
            k.audit_overflow_pending(),
            k.audit_overflow_total(),
            k.verify_audit_chain().is_ok(),
        )
    };
    let knot_nodes = crate::substrate::knot_rebuild::knot_node_count(state);
    json!({
        "schema": "kernel_durability.v1",
        "flush_interval_sec": flush_interval_secs(),
        "last_flush_ms": state.kernel_durability.last_flush_ms(),
        "last_flush_objects": state.kernel_durability.last_flush_objects(),
        "last_flush_error": state.kernel_durability.last_flush_error(),
        "kernel_packets": packet_count,
        "kernel_agents": agent_count,
        "audit_batch_pending": audit_pending,
        "audit_overflow_pending": audit_overflow_pending,
        "audit_overflow_total": audit_overflow_total,
        "audit_chain_integrity": chain_ok,
        "knot_node_count": knot_nodes,
        "memwrite_write_through": crate::substrate::memwrite_durability::write_through_enabled(),
        "write_through_total": state.kernel_durability.last_write_through_total(),
        "wal_status": if crate::substrate::memwrite_durability::write_through_enabled() {
            "write_through"
        } else if audit_overflow_pending > 0 || audit_pending > 100 {
            "lag"
        } else {
            "interval_flush"
        },
        "honesty_note": "Write-through when CONNECTOR_MEMWRITE_SYNC_FLUSH=1 or production; else periodic redb flush",
    })
}

impl KernelDurabilityTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_flush_ok(&self, objects: usize) {
        self.last_flush_ms.store(
            chrono::Utc::now().timestamp_millis(),
            std::sync::atomic::Ordering::Relaxed,
        );
        self.last_flush_objects.store(
            objects as u64,
            std::sync::atomic::Ordering::Relaxed,
        );
        if let Ok(mut e) = self.last_flush_error.lock() {
            *e = None;
        }
    }

    pub fn record_flush_err(&self, msg: String) {
        if let Ok(mut e) = self.last_flush_error.lock() {
            *e = Some(msg);
        }
    }

    pub fn record_write_through_ok(&self) {
        self.write_through_total.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Ok(mut e) = self.last_flush_error.lock() {
            *e = None;
        }
    }

    pub fn last_write_through_total(&self) -> u64 {
        self.write_through_total
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn last_flush_ms(&self) -> i64 {
        self.last_flush_ms.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn last_flush_objects(&self) -> u64 {
        self.last_flush_objects.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn last_flush_error(&self) -> Option<String> {
        self.last_flush_error.lock().ok().and_then(|g| g.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durability_tracker_records_flush_ok_and_clears_error() {
        let t = KernelDurabilityTracker::default();
        t.record_flush_err("disk full".into());
        assert_eq!(t.last_flush_error(), Some("disk full".into()));

        t.record_flush_ok(42);
        assert_eq!(t.last_flush_objects(), 42);
        assert!(t.last_flush_ms() > 0);
        assert_eq!(t.last_flush_error(), None);
    }

    #[test]
    fn durability_tracker_accumulates_errors_until_success() {
        let t = KernelDurabilityTracker::default();
        t.record_flush_err("timeout".into());
        t.record_flush_err("still down".into());
        assert_eq!(t.last_flush_error(), Some("still down".into()));
        t.record_flush_ok(1);
        assert_eq!(t.last_flush_error(), None);
    }
}
