//! MemWrite write-through persistence (I-03) — optional immediate `store_packet` after dispatch.

use vac_core::kernel::MemoryKernel;
use vac_core::types::MemPacket;

use crate::state::{PlatformState, SharedState};

/// When true, successful MemWrite dispatches are persisted to `kernel_store` immediately.
/// Default ON. Set CONNECTOR_MEMWRITE_SYNC_FLUSH=0 only for explicit lab RPO trade-off.
pub fn write_through_enabled() -> bool {
    match std::env::var("CONNECTOR_MEMWRITE_SYNC_FLUSH") {
        Ok(v) if v == "0" || v.eq_ignore_ascii_case("false") || v.eq_ignore_ascii_case("off") => {
            false
        }
        _ => true,
    }
}

/// After successful MemWrite: persist kernel state when write-through is enabled.
pub fn sync_after_memwrite(state: &PlatformState) -> Result<(), String> {
    if !write_through_enabled() {
        return Ok(());
    }
    let mut kernel = state.kernel.lock().map_err(|e| format!("kernel_lock:{e}"))?;
    kernel.flush_audit_batch();
    let mut store = state
        .kernel_store
        .lock()
        .map_err(|e| format!("kernel_store_lock:{e}"))?;
    match kernel.flush_to_store(&mut **store) {
        Ok(n) => {
            state.kernel_durability.record_write_through_ok();
            if n > 0 {
                state.kernel_durability.record_flush_ok(n);
            }
            Ok(())
        }
        Err(e) => {
            let msg = format!("MemWrite sync flush failed: {e}");
            state.kernel_durability.record_flush_err(msg.clone());
            tracing::warn!(error = %e, "MemWrite sync flush failed");
            Err(msg)
        }
    }
}

/// Persist a single packet (legacy path — prefer `sync_after_memwrite` for crash safety).
pub fn write_through_packet(state: &PlatformState, packet: &MemPacket) -> Result<(), String> {
    let _ = packet;
    sync_after_memwrite(state)
}

pub fn write_through_packet_shared(state: &SharedState, packet: &MemPacket) -> Result<(), String> {
    let _ = packet;
    sync_after_memwrite(state.as_ref())
}

/// Drain kernel audit overflow buffer and persist entries to the backing store.
pub fn drain_and_persist_audit_overflow(state: &PlatformState, kernel: &mut MemoryKernel) {
    let overflow = kernel.drain_audit_overflow();
    if overflow.is_empty() {
        return;
    }
    let mut store = state.kernel_store.lock().unwrap();
    for entry in &overflow {
        if let Err(e) = store.store_audit_entry(entry) {
            state
                .kernel_durability
                .record_flush_err(format!("audit overflow persist: {e}"));
            tracing::warn!(error = %e, "failed to persist audit overflow entry");
            break;
        }
    }
}

