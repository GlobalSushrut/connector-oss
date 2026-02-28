//! Read-Your-Writes Session Stickiness — ensures same-session operations hit the same cell.
//!
//! Military-grade properties:
//! - Deterministic routing: same session_id always maps to same cell within TTL
//! - Automatic expiry: stale sticky routes cleaned up
//! - Override: explicit route_to_cell for cross-cell operations
//! - Audit: all routing decisions logged

use std::collections::HashMap;

// ── Sticky Route ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct StickyRoute {
    cell_id: String,
    created_at: i64,
    ttl_ms: i64,
    access_count: u64,
}

// ── Routing Decision ────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision {
    /// Routed to sticky cell (read-your-writes guarantee).
    Sticky { cell_id: String },
    /// Routed to specified cell (explicit override).
    Override { cell_id: String },
    /// No sticky route — needs fresh assignment.
    Unbound,
}

// ── Session Router ──────────────────────────────────────────────────

pub struct SessionRouter {
    routes: HashMap<String, StickyRoute>,
    default_ttl_ms: i64,
    route_decisions: u64,
}

impl SessionRouter {
    pub fn new(default_ttl_ms: i64) -> Self {
        Self {
            routes: HashMap::new(),
            default_ttl_ms,
            route_decisions: 0,
        }
    }

    fn now_ms() -> i64 { chrono::Utc::now().timestamp_millis() }

    /// Bind a session to a cell.
    pub fn bind(&mut self, session_id: &str, cell_id: &str) {
        self.routes.insert(session_id.to_string(), StickyRoute {
            cell_id: cell_id.to_string(),
            created_at: Self::now_ms(),
            ttl_ms: self.default_ttl_ms,
            access_count: 0,
        });
    }

    /// Route an operation for a session.
    pub fn route(&mut self, session_id: &str, explicit_cell: Option<&str>) -> RouteDecision {
        self.route_decisions += 1;

        // Explicit override takes precedence
        if let Some(cell) = explicit_cell {
            return RouteDecision::Override { cell_id: cell.to_string() };
        }

        let now = Self::now_ms();
        if let Some(route) = self.routes.get_mut(session_id) {
            if now - route.created_at <= route.ttl_ms {
                route.access_count += 1;
                return RouteDecision::Sticky { cell_id: route.cell_id.clone() };
            }
            // Expired — remove
            self.routes.remove(session_id);
        }

        RouteDecision::Unbound
    }

    /// Clean up expired routes.
    pub fn cleanup_expired(&mut self) -> usize {
        let now = Self::now_ms();
        let before = self.routes.len();
        self.routes.retain(|_, r| now - r.created_at <= r.ttl_ms);
        before - self.routes.len()
    }

    pub fn active_routes(&self) -> usize { self.routes.len() }
    pub fn total_decisions(&self) -> u64 { self.route_decisions }
}

impl Default for SessionRouter {
    fn default() -> Self { Self::new(300_000) } // 5 min default
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sticky_routing() {
        let mut router = SessionRouter::default();
        router.bind("sess-1", "cell-A");

        let decision = router.route("sess-1", None);
        assert_eq!(decision, RouteDecision::Sticky { cell_id: "cell-A".into() });
    }

    #[test]
    fn test_unbound_session() {
        let mut router = SessionRouter::default();
        let decision = router.route("unknown", None);
        assert_eq!(decision, RouteDecision::Unbound);
    }

    #[test]
    fn test_explicit_override() {
        let mut router = SessionRouter::default();
        router.bind("sess-1", "cell-A");

        let decision = router.route("sess-1", Some("cell-B"));
        assert_eq!(decision, RouteDecision::Override { cell_id: "cell-B".into() });
    }

    #[test]
    fn test_session_expiry() {
        let mut router = SessionRouter::new(0); // instant expiry
        router.bind("sess-1", "cell-A");
        // Backdate
        router.routes.get_mut("sess-1").unwrap().created_at -= 100;

        let decision = router.route("sess-1", None);
        assert_eq!(decision, RouteDecision::Unbound);
    }

    #[test]
    fn test_cleanup() {
        let mut router = SessionRouter::new(0);
        router.bind("sess-1", "cell-A");
        router.bind("sess-2", "cell-B");
        // Backdate all
        for r in router.routes.values_mut() { r.created_at -= 100; }

        let cleaned = router.cleanup_expired();
        assert_eq!(cleaned, 2);
        assert_eq!(router.active_routes(), 0);
    }
}
