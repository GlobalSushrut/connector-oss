//! KernelHandle — Temporal-style Activity layer for VAC / MemoryKernel I/O.
//!
//! Async handlers orchestrate; this module runs blocking kernel work on the
//! tokio blocking pool so the async runtime (and `/health`) stay responsive.

use std::sync::Arc;
use std::time::Duration;

use vac_core::kernel::MemoryKernel;

use crate::state::{PlatformState, SharedState};

/// Default max wait for readiness probes that must touch the kernel briefly.
pub const READY_TRY_LOCK_TIMEOUT: Duration = Duration::from_millis(50);

/// Run a closure that needs exclusive access to [`MemoryKernel`] off the async
/// worker threads.
pub async fn with_kernel_mut<F, R>(state: SharedState, f: F) -> Result<R, String>
where
    F: FnOnce(&mut MemoryKernel) -> R + Send + 'static,
    R: Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut guard = state
            .kernel
            .lock()
            .map_err(|_| "kernel_lock_poisoned".to_string())?;
        Ok(f(&mut *guard))
    })
    .await
    .map_err(|e| format!("kernel_spawn_blocking_join: {e}"))?
}

/// Run a read-only kernel closure on the blocking pool.
pub async fn with_kernel<F, R>(state: SharedState, f: F) -> Result<R, String>
where
    F: FnOnce(&MemoryKernel) -> R + Send + 'static,
    R: Send + 'static,
{
    with_kernel_mut(state, move |k| f(k)).await
}

/// Build agent RAG context without blocking the async runtime.
pub async fn build_agent_rag_context_async(
    state: SharedState,
    agent_pid: String,
    fallback_namespace: String,
    user_query: String,
) -> String {
    if !crate::services::gateway::playground_rag_enabled() {
        return String::new();
    }
    if user_query.trim().is_empty() {
        return String::new();
    }
    let state2 = Arc::clone(&state);
    tokio::task::spawn_blocking(move || {
        crate::services::gateway::build_agent_rag_context(
            state2.as_ref(),
            &agent_pid,
            &fallback_namespace,
            &user_query,
        )
    })
    .await
    .unwrap_or_else(|e| {
        tracing::warn!(error = %e, "rag_spawn_blocking_join_failed");
        String::new()
    })
}

/// Try to lock the kernel within `timeout` (for `/ready` probes).
/// Returns `None` if the lock could not be acquired in time.
pub fn try_lock_kernel_for(
    state: &PlatformState,
    timeout: Duration,
) -> Option<std::sync::MutexGuard<'_, MemoryKernel>> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match state.kernel.try_lock() {
            Ok(guard) => return Some(guard),
            Err(std::sync::TryLockError::Poisoned(p)) => return Some(p.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => {
                if std::time::Instant::now() >= deadline {
                    return None;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    #[test]
    fn try_lock_times_out_when_held() {
        let m = Arc::new(Mutex::new(0u32));
        let m2 = Arc::clone(&m);
        let _hold = m2.lock().unwrap();
        let start = Instant::now();
        let deadline = start + Duration::from_millis(20);
        let mut got = false;
        loop {
            match m.try_lock() {
                Ok(_) => {
                    got = true;
                    break;
                }
                Err(std::sync::TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(std::sync::TryLockError::Poisoned(_)) => break,
            }
        }
        assert!(!got);
        assert!(start.elapsed() >= Duration::from_millis(15));
    }
}
