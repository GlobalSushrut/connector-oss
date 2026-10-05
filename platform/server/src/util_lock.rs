//! OPS-10 — Bounded lock helpers (poison → Err, never panic on request paths).

use std::sync::{Mutex, MutexGuard, RwLock, RwLockReadGuard};

/// Lock a mutex or return a bounded error string (no panic on poison).
pub fn mutex_lock<'a, T>(m: &'a Mutex<T>, ctx: &str) -> Result<MutexGuard<'a, T>, String> {
    m.lock()
        .map_err(|_| format!("{ctx}_lock_poisoned"))
}

/// Read-lock or return a bounded error string.
pub fn rwlock_read<'a, T>(m: &'a RwLock<T>, ctx: &str) -> Result<RwLockReadGuard<'a, T>, String> {
    m.read()
        .map_err(|_| format!("{ctx}_rwlock_poisoned"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn poisoned_mutex_returns_err_not_panic() {
        let m = Arc::new(Mutex::new(1u32));
        let m2 = m.clone();
        let _ = std::thread::spawn(move || {
            let _g = m2.lock().unwrap();
            panic!("poison");
        })
        .join();
        let err = mutex_lock(&m, "test").unwrap_err();
        assert!(err.contains("poisoned"), "{err}");
    }
}
