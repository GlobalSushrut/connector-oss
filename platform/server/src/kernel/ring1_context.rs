//! Per-request execution quantum — extracted once at the HTTP edge and visible to
//! every `admission::check` on that task (blackhat bypass: handler forgot headers).

use std::cell::RefCell;
use std::future::Future;

tokio::task_local! {
    static EXECUTION_QUANTUM: RefCell<Option<String>>;
}

/// Run `f` with the quantum id bound for this async task (from middleware or MCP handle).
pub async fn scope<F, T>(quantum: Option<String>, f: F) -> T
where
    F: Future<Output = T>,
{
    EXECUTION_QUANTUM
        .scope(RefCell::new(quantum), f)
        .await
}

/// Quantum on the current task, if middleware or an explicit scope set it.
pub fn current() -> Option<String> {
    EXECUTION_QUANTUM
        .try_with(|c| c.borrow().clone())
        .ok()
        .flatten()
}

/// Prefer explicit caller id; fall back to request-scoped task local.
pub fn resolve_quantum_id(explicit: Option<&str>) -> Option<String> {
    explicit
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .or_else(current)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn scope_makes_quantum_visible() {
        scope(Some("q_test".into()), async {
            assert_eq!(current().as_deref(), Some("q_test"));
            assert_eq!(resolve_quantum_id(None).as_deref(), Some("q_test"));
            assert_eq!(resolve_quantum_id(Some("explicit")).as_deref(), Some("explicit"));
        })
        .await;
        assert!(current().is_none());
    }
}
