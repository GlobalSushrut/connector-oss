//! Session single-writer — one Talk turn at a time per session key.
//!
//! Prevents concurrent consults from lock-convoying the kernel and orphaning
//! user events mid-turn (INV: session shard single writer).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};

/// Per-session async mutex + touch time.
struct SessionSlot {
    lock: Arc<AsyncMutex<()>>,
    last_touch: Mutex<Instant>,
}

impl SessionSlot {
    fn new() -> Self {
        Self {
            lock: Arc::new(AsyncMutex::new(())),
            last_touch: Mutex::new(Instant::now()),
        }
    }

    fn touch(&self) {
        if let Ok(mut t) = self.last_touch.lock() {
            *t = Instant::now();
        }
    }
}

#[derive(Default)]
pub struct SessionOwnerRegistry {
    slots: Mutex<HashMap<String, Arc<SessionSlot>>>,
}

impl SessionOwnerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    fn slot(&self, key: &str) -> Arc<SessionSlot> {
        let mut g = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        g.entry(key.to_string())
            .or_insert_with(|| Arc::new(SessionSlot::new()))
            .clone()
    }

    /// Acquire exclusive Talk ownership for `session_key` (typically agent_pid or session_id).
    pub async fn acquire(&self, session_key: &str) -> SessionLease {
        let slot = self.slot(session_key);
        slot.touch();
        let guard = slot.lock.clone().lock_owned().await;
        slot.touch();
        SessionLease {
            key: session_key.to_string(),
            _guard: guard,
        }
    }

    /// Non-blocking acquire — Err when another turn holds the session.
    pub fn try_acquire(&self, session_key: &str) -> Result<SessionLease, String> {
        let slot = self.slot(session_key);
        match slot.lock.clone().try_lock_owned() {
            Ok(guard) => {
                slot.touch();
                Ok(SessionLease {
                    key: session_key.to_string(),
                    _guard: guard,
                })
            }
            Err(_) => Err(format!(
                "session_busy: another Talk turn holds session={session_key}"
            )),
        }
    }

    /// Drop idle slots (best-effort hygiene).
    pub fn reap_idle(&self, older_than: Duration) {
        let mut g = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        g.retain(|_, slot| {
            slot.last_touch
                .lock()
                .map(|t| t.elapsed() < older_than)
                .unwrap_or(true)
        });
    }
}

pub struct SessionLease {
    pub key: String,
    _guard: OwnedMutexGuard<()>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn try_acquire_rejects_second_writer() {
        let reg = SessionOwnerRegistry::new();
        let _a = reg.acquire("s1").await;
        assert!(reg.try_acquire("s1").is_err());
    }

    #[tokio::test]
    async fn release_allows_next() {
        let reg = SessionOwnerRegistry::new();
        {
            let _a = reg.acquire("s2").await;
        }
        assert!(reg.try_acquire("s2").is_ok());
    }
}
