//! AAPI Gateway ↔ Engine Bridge — connects the AAPI HTTP gateway to the connector engine.
//!
//! The AAPI Gateway (`aapi-gateway`) is a standalone HTTP server that receives
//! VĀKYA submissions. This bridge module defines the interface for the engine
//! to receive dispatched VAKYAs from the gateway and return results.
//!
//! Architecture:
//! ```text
//! HTTP Client → AAPI Gateway → GatewayBridge → ConnectorEngine → MemoryKernel
//! ```
//!
//! The bridge is trait-based so it can be implemented without pulling in
//! aapi-gateway's heavy deps (axum, SQLite, etc.) into connector-engine.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ═══════════════════════════════════════════════════════════════
// Gateway Request/Response Types
// ═══════════════════════════════════════════════════════════════

/// A VĀKYA execution request forwarded from the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayRequest {
    /// Request ID (from gateway)
    pub request_id: String,
    /// Actor (agent DID or identity)
    pub actor: String,
    /// Action to perform (e.g., "memory.write", "tool.call")
    pub action: String,
    /// Resource target (e.g., "ns:patient:123")
    pub resource: Option<String>,
    /// Request payload
    pub payload: serde_json::Value,
    /// Capability token (if gateway requires capabilities)
    pub capability_token: Option<String>,
    /// Request timestamp (ms epoch)
    pub timestamp_ms: u64,
    /// Gateway ID that forwarded this request
    pub gateway_id: String,
}

/// Response sent back to the gateway.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayResponse {
    pub request_id: String,
    pub status: GatewayStatus,
    pub result: Option<serde_json::Value>,
    pub error: Option<String>,
    pub audit_id: Option<String>,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GatewayStatus {
    Success,
    Denied,
    Error,
    Timeout,
    RateLimited,
}

// ═══════════════════════════════════════════════════════════════
// Gateway Bridge Trait
// ═══════════════════════════════════════════════════════════════

/// Trait for bridging AAPI Gateway requests to the connector engine.
pub trait GatewayHandler: Send + Sync {
    /// Handle a gateway request and return a response.
    fn handle(&self, request: &GatewayRequest) -> GatewayResponse;
}

// ═══════════════════════════════════════════════════════════════
// Default Bridge (routes to kernel dispatch)
// ═══════════════════════════════════════════════════════════════

/// Default gateway bridge that validates and routes requests.
pub struct DefaultGatewayBridge {
    /// Allowed actions (if empty, all actions allowed)
    pub allowed_actions: Vec<String>,
    /// Rate limit: max requests per second per actor
    pub rate_limit_per_sec: u64,
    /// Request counters: actor → (count, last_reset_ms)
    counters: HashMap<String, (u64, u64)>,
    /// Total requests handled
    pub total_handled: u64,
    /// Total denied
    pub total_denied: u64,
}

impl DefaultGatewayBridge {
    pub fn new() -> Self {
        Self {
            allowed_actions: Vec::new(),
            rate_limit_per_sec: 100,
            counters: HashMap::new(),
            total_handled: 0,
            total_denied: 0,
        }
    }

    pub fn with_allowed_actions(mut self, actions: Vec<String>) -> Self {
        self.allowed_actions = actions;
        self
    }

    pub fn with_rate_limit(mut self, per_sec: u64) -> Self {
        self.rate_limit_per_sec = per_sec;
        self
    }

    /// Check if action is allowed.
    fn is_action_allowed(&self, action: &str) -> bool {
        self.allowed_actions.is_empty() || self.allowed_actions.iter().any(|a| a == action)
    }

    /// Check rate limit for an actor.
    fn check_rate_limit(&mut self, actor: &str, now_ms: u64) -> bool {
        let entry = self.counters.entry(actor.to_string()).or_insert((0, now_ms));
        // Reset counter every second
        if now_ms - entry.1 >= 1000 {
            entry.0 = 0;
            entry.1 = now_ms;
        }
        entry.0 += 1;
        entry.0 <= self.rate_limit_per_sec
    }
}

impl GatewayHandler for DefaultGatewayBridge {
    fn handle(&self, request: &GatewayRequest) -> GatewayResponse {
        // Check action allowlist
        if !self.is_action_allowed(&request.action) {
            return GatewayResponse {
                request_id: request.request_id.clone(),
                status: GatewayStatus::Denied,
                result: None,
                error: Some(format!("Action '{}' not allowed", request.action)),
                audit_id: None,
                latency_ms: 0,
            };
        }

        // If we reach here, the request is valid — return success placeholder
        // In production, this dispatches to the MemoryKernel via DualDispatcher
        GatewayResponse {
            request_id: request.request_id.clone(),
            status: GatewayStatus::Success,
            result: Some(serde_json::json!({
                "action": request.action,
                "actor": request.actor,
                "handled_by": "connector-engine",
            })),
            error: None,
            audit_id: Some(format!("audit:{}", request.request_id)),
            latency_ms: 1,
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// Gateway Bridge Manager
// ═══════════════════════════════════════════════════════════════

/// Manages gateway connections and routes requests.
pub struct GatewayBridgeManager {
    bridge: DefaultGatewayBridge,
    /// Connected gateways
    connected_gateways: Vec<String>,
}

impl GatewayBridgeManager {
    pub fn new() -> Self {
        Self {
            bridge: DefaultGatewayBridge::new(),
            connected_gateways: Vec::new(),
        }
    }

    pub fn with_bridge(mut self, bridge: DefaultGatewayBridge) -> Self {
        self.bridge = bridge;
        self
    }

    pub fn register_gateway(&mut self, gateway_id: impl Into<String>) {
        self.connected_gateways.push(gateway_id.into());
    }

    pub fn handle_request(&mut self, request: &GatewayRequest) -> GatewayResponse {
        // Check rate limit (needs &mut self)
        if !self.bridge.check_rate_limit(&request.actor, request.timestamp_ms) {
            self.bridge.total_denied += 1;
            return GatewayResponse {
                request_id: request.request_id.clone(),
                status: GatewayStatus::RateLimited,
                result: None,
                error: Some("Rate limit exceeded".into()),
                audit_id: None,
                latency_ms: 0,
            };
        }
        self.bridge.total_handled += 1;
        self.bridge.handle(request)
    }

    pub fn gateway_count(&self) -> usize {
        self.connected_gateways.len()
    }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn make_request(action: &str, actor: &str) -> GatewayRequest {
        GatewayRequest {
            request_id: format!("req:{}", action),
            actor: actor.into(),
            action: action.into(),
            resource: None,
            payload: serde_json::json!({}),
            capability_token: None,
            timestamp_ms: 1000,
            gateway_id: "gw:test".into(),
        }
    }

    #[test]
    fn test_default_bridge_allows_all() {
        let bridge = DefaultGatewayBridge::new();
        let req = make_request("memory.write", "agent:a");
        let resp = bridge.handle(&req);
        assert_eq!(resp.status, GatewayStatus::Success);
        assert!(resp.audit_id.is_some());
    }

    #[test]
    fn test_action_allowlist_denies() {
        let bridge = DefaultGatewayBridge::new()
            .with_allowed_actions(vec!["memory.read".into()]);
        let req = make_request("memory.write", "agent:a");
        let resp = bridge.handle(&req);
        assert_eq!(resp.status, GatewayStatus::Denied);
    }

    #[test]
    fn test_action_allowlist_permits() {
        let bridge = DefaultGatewayBridge::new()
            .with_allowed_actions(vec!["memory.write".into()]);
        let req = make_request("memory.write", "agent:a");
        let resp = bridge.handle(&req);
        assert_eq!(resp.status, GatewayStatus::Success);
    }

    #[test]
    fn test_rate_limiting() {
        let bridge = DefaultGatewayBridge::new().with_rate_limit(2);
        let mut mgr = GatewayBridgeManager::new().with_bridge(bridge);

        let req = make_request("test", "agent:a");
        assert_eq!(mgr.handle_request(&req).status, GatewayStatus::Success);
        assert_eq!(mgr.handle_request(&req).status, GatewayStatus::Success);
        assert_eq!(mgr.handle_request(&req).status, GatewayStatus::RateLimited);
    }

    #[test]
    fn test_rate_limit_resets_after_window() {
        let bridge = DefaultGatewayBridge::new().with_rate_limit(1);
        let mut mgr = GatewayBridgeManager::new().with_bridge(bridge);

        let mut req = make_request("test", "agent:a");
        req.timestamp_ms = 1000;
        assert_eq!(mgr.handle_request(&req).status, GatewayStatus::Success);
        assert_eq!(mgr.handle_request(&req).status, GatewayStatus::RateLimited);

        // Advance time past 1 second
        req.timestamp_ms = 2001;
        assert_eq!(mgr.handle_request(&req).status, GatewayStatus::Success);
    }

    #[test]
    fn test_gateway_registration() {
        let mut mgr = GatewayBridgeManager::new();
        mgr.register_gateway("gw:1");
        mgr.register_gateway("gw:2");
        assert_eq!(mgr.gateway_count(), 2);
    }

    #[test]
    fn test_response_contains_audit_id() {
        let bridge = DefaultGatewayBridge::new();
        let req = make_request("tool.call", "agent:b");
        let resp = bridge.handle(&req);
        assert_eq!(resp.audit_id, Some("audit:req:tool.call".into()));
    }

    #[test]
    fn test_different_actors_independent_rate_limits() {
        let bridge = DefaultGatewayBridge::new().with_rate_limit(1);
        let mut mgr = GatewayBridgeManager::new().with_bridge(bridge);

        let req_a = make_request("test", "agent:a");
        let req_b = make_request("test", "agent:b");
        assert_eq!(mgr.handle_request(&req_a).status, GatewayStatus::Success);
        assert_eq!(mgr.handle_request(&req_b).status, GatewayStatus::Success);
        // Both hit their limit
        assert_eq!(mgr.handle_request(&req_a).status, GatewayStatus::RateLimited);
        assert_eq!(mgr.handle_request(&req_b).status, GatewayStatus::RateLimited);
    }
}
