//! Surface Routing — Command-to-Surface mapping
//!
//! Routes commands to appropriate surfaces with fallback handling.

use super::document::{SurfaceType, SurfaceView};
use serde::{Deserialize, Serialize};

/// Route definition for command-to-surface mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceRoute {
    pub verb: &'static str,
    pub noun: &'static str,
    pub surface: SurfaceType,
    pub default_view: SurfaceView,
    pub fallback: Option<SurfaceType>,
}

/// Surface router for command routing
pub struct SurfaceRouter {
    routes: Vec<SurfaceRoute>,
}

impl Default for SurfaceRouter {
    fn default() -> Self { Self::new() }
}

impl SurfaceRouter {
    pub fn new() -> Self {
        Self {
            routes: vec![
                // Agent commands
                SurfaceRoute { verb: "inspect", noun: "agent", surface: SurfaceType::Agent, default_view: SurfaceView::Summary, fallback: None },
                SurfaceRoute { verb: "debug", noun: "agent", surface: SurfaceType::Debug, default_view: SurfaceView::Ops, fallback: Some(SurfaceType::Agent) },
                SurfaceRoute { verb: "health", noun: "agent", surface: SurfaceType::Health, default_view: SurfaceView::Ops, fallback: Some(SurfaceType::Agent) },
                SurfaceRoute { verb: "trace", noun: "agent", surface: SurfaceType::Trace, default_view: SurfaceView::Ops, fallback: Some(SurfaceType::Debug) },
                
                // Audit commands
                SurfaceRoute { verb: "audit", noun: "agent", surface: SurfaceType::Audit, default_view: SurfaceView::Summary, fallback: Some(SurfaceType::Agent) },
                SurfaceRoute { verb: "audit", noun: "memory", surface: SurfaceType::Audit, default_view: SurfaceView::Summary, fallback: Some(SurfaceType::Memory) },
                SurfaceRoute { verb: "investigate", noun: "*", surface: SurfaceType::Audit, default_view: SurfaceView::Forensic, fallback: None },
                
                // Memory commands
                SurfaceRoute { verb: "inspect", noun: "memory", surface: SurfaceType::Memory, default_view: SurfaceView::Summary, fallback: None },
                SurfaceRoute { verb: "review", noun: "memory", surface: SurfaceType::Review, default_view: SurfaceView::Summary, fallback: Some(SurfaceType::Memory) },
                SurfaceRoute { verb: "cat", noun: "memory", surface: SurfaceType::Inspect, default_view: SurfaceView::Ops, fallback: Some(SurfaceType::Memory) },
                
                // Compliance commands
                SurfaceRoute { verb: "compliance", noun: "*", surface: SurfaceType::Compliance, default_view: SurfaceView::Summary, fallback: None },
                SurfaceRoute { verb: "verify", noun: "*", surface: SurfaceType::Proof, default_view: SurfaceView::Ops, fallback: Some(SurfaceType::Audit) },
                
                // Books commands
                SurfaceRoute { verb: "books", noun: "*", surface: SurfaceType::Books, default_view: SurfaceView::Ops, fallback: None },
                SurfaceRoute { verb: "ledger", noun: "*", surface: SurfaceType::Books, default_view: SurfaceView::Ops, fallback: None },
                
                // Knowledge commands
                SurfaceRoute { verb: "inspect", noun: "knowledge", surface: SurfaceType::Knowledge, default_view: SurfaceView::Summary, fallback: None },
                
                // Tool commands
                SurfaceRoute { verb: "inspect", noun: "tool", surface: SurfaceType::Tool, default_view: SurfaceView::Summary, fallback: None },
                
                // Policy commands
                SurfaceRoute { verb: "inspect", noun: "policy", surface: SurfaceType::Policy, default_view: SurfaceView::Summary, fallback: None },
                
                // Contract commands
                SurfaceRoute { verb: "inspect", noun: "contract", surface: SurfaceType::Contract, default_view: SurfaceView::Summary, fallback: None },
                
                // Explain commands
                SurfaceRoute { verb: "explain", noun: "*", surface: SurfaceType::Explain, default_view: SurfaceView::Summary, fallback: None },
                
                // Monitor commands
                SurfaceRoute { verb: "monitor", noun: "*", surface: SurfaceType::Monitor, default_view: SurfaceView::Ops, fallback: None },
                SurfaceRoute { verb: "watch", noun: "*", surface: SurfaceType::Monitor, default_view: SurfaceView::Ops, fallback: None },
            ],
        }
    }

    /// Find route for a command
    pub fn route(&self, verb: &str, noun: &str) -> Option<&SurfaceRoute> {
        // Try exact match first
        if let Some(route) = self.routes.iter().find(|r| r.verb == verb && r.noun == noun) {
            return Some(route);
        }
        // Try wildcard noun match
        self.routes.iter().find(|r| r.verb == verb && r.noun == "*")
    }

    /// Get surface type for command
    pub fn surface_for(&self, verb: &str, noun: &str) -> SurfaceType {
        self.route(verb, noun).map(|r| r.surface).unwrap_or(SurfaceType::Inspect)
    }

    /// Get default view for command
    pub fn default_view_for(&self, verb: &str, noun: &str) -> SurfaceView {
        self.route(verb, noun).map(|r| r.default_view).unwrap_or(SurfaceView::Summary)
    }

    /// Add custom route
    pub fn add_route(&mut self, route: SurfaceRoute) {
        self.routes.push(route);
    }
}

/// Routing context with resolved surface info
#[derive(Debug, Clone)]
pub struct RoutingContext {
    pub surface_type: SurfaceType,
    pub view: SurfaceView,
    pub fallback: Option<SurfaceType>,
    pub subject_id: String,
    pub namespace: Option<String>,
}

impl RoutingContext {
    pub fn resolve(verb: &str, noun: &str, subject: &str, view_override: Option<SurfaceView>) -> Self {
        let router = SurfaceRouter::new();
        let route = router.route(verb, noun);
        Self {
            surface_type: route.map(|r| r.surface).unwrap_or(SurfaceType::Inspect),
            view: view_override.unwrap_or_else(|| route.map(|r| r.default_view).unwrap_or(SurfaceView::Summary)),
            fallback: route.and_then(|r| r.fallback),
            subject_id: subject.to_string(),
            namespace: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routing() {
        let router = SurfaceRouter::new();
        
        assert_eq!(router.surface_for("debug", "agent"), SurfaceType::Debug);
        assert_eq!(router.surface_for("audit", "agent"), SurfaceType::Audit);
        assert_eq!(router.surface_for("compliance", "hipaa"), SurfaceType::Compliance);
    }

    #[test]
    fn test_wildcard_routing() {
        let router = SurfaceRouter::new();
        
        // Wildcard matches
        assert_eq!(router.surface_for("explain", "anything"), SurfaceType::Explain);
        assert_eq!(router.surface_for("monitor", "agent"), SurfaceType::Monitor);
    }

    #[test]
    fn test_routing_context() {
        let ctx = RoutingContext::resolve("debug", "agent", "claims-001", None);
        assert_eq!(ctx.surface_type, SurfaceType::Debug);
        assert_eq!(ctx.view, SurfaceView::Ops);
    }
}
