//! Routing Layer (Layer 4) — Content-addressed routing, cell mesh, discovery.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::envelope::{Envelope, Recipient};
use crate::identity::EntityId;
use crate::error::{ProtocolError, ProtoResult};

// ── Routing Strategy ────────────────────────────────────────────────

/// How to route a message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingStrategy {
    /// Direct: sender → recipient (same cell).
    Direct,
    /// Relay: sender → gateway → recipient (cross-cell).
    Relay { gateway: String },
    /// Multicast: sender → all entities with a capability.
    Multicast { capability: String },
    /// Broadcast: sender → all entities in cell (admin only).
    Broadcast { cell_id: String },
    /// Emergency: sender → ALL entities (e-stop). Bypasses all queues.
    Emergency,
}

// ── Route Entry ─────────────────────────────────────────────────────

/// A routing table entry.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub entity_id: EntityId,
    pub cell_id: String,
    pub endpoint: String,
    pub is_local: bool,
    pub last_seen: i64,
}

// ── Router ──────────────────────────────────────────────────────────

/// Routes messages to entities across cells.
pub struct Router {
    local_cell_id: String,
    /// entity_id → route entry
    routes: HashMap<EntityId, RouteEntry>,
    /// capability → list of entity_ids that have it
    capability_index: HashMap<String, Vec<EntityId>>,
    /// cell_id → gateway endpoint
    gateways: HashMap<String, String>,
}

impl Router {
    pub fn new(local_cell_id: &str) -> Self {
        Self {
            local_cell_id: local_cell_id.to_string(),
            routes: HashMap::new(),
            capability_index: HashMap::new(),
            gateways: HashMap::new(),
        }
    }

    /// Register an entity route.
    pub fn add_route(&mut self, entity_id: EntityId, cell_id: &str, endpoint: &str) {
        let is_local = cell_id == self.local_cell_id;
        self.routes.insert(entity_id.clone(), RouteEntry {
            entity_id,
            cell_id: cell_id.to_string(),
            endpoint: endpoint.to_string(),
            is_local,
            last_seen: chrono::Utc::now().timestamp_millis(),
        });
    }

    /// Register entity capabilities for multicast routing.
    pub fn register_capabilities(&mut self, entity_id: EntityId, capabilities: Vec<String>) {
        for cap in capabilities {
            self.capability_index.entry(cap).or_default().push(entity_id.clone());
        }
    }

    /// Register a cross-cell gateway.
    pub fn add_gateway(&mut self, cell_id: &str, endpoint: &str) {
        self.gateways.insert(cell_id.to_string(), endpoint.to_string());
    }

    /// Resolve the routing strategy for an envelope.
    pub fn resolve(&self, envelope: &Envelope) -> ProtoResult<RoutingStrategy> {
        // Emergency messages always use emergency routing
        if envelope.message_type.is_safety_critical() {
            return Ok(RoutingStrategy::Emergency);
        }

        match &envelope.recipient {
            Recipient::Entity(id) => {
                if let Some(route) = self.routes.get(id) {
                    if route.is_local {
                        Ok(RoutingStrategy::Direct)
                    } else if let Some(gw) = self.gateways.get(&route.cell_id) {
                        Ok(RoutingStrategy::Relay { gateway: gw.clone() })
                    } else {
                        Err(ProtocolError::Routing(format!(
                            "No gateway for cell {}", route.cell_id
                        )))
                    }
                } else {
                    Err(ProtocolError::Routing(format!("Unknown entity {}", id)))
                }
            }
            Recipient::Capability(cap) => {
                Ok(RoutingStrategy::Multicast { capability: cap.clone() })
            }
            Recipient::Cell(cell_id) => {
                Ok(RoutingStrategy::Broadcast { cell_id: cell_id.clone() })
            }
            Recipient::Broadcast => {
                Ok(RoutingStrategy::Broadcast { cell_id: self.local_cell_id.clone() })
            }
        }
    }

    /// Get entities for a multicast capability.
    pub fn multicast_targets(&self, capability: &str) -> Vec<&EntityId> {
        self.capability_index.get(capability)
            .map(|ids| ids.iter().collect())
            .unwrap_or_default()
    }

    /// Remove stale routes (not seen within threshold).
    pub fn remove_stale(&mut self, threshold_ms: i64) -> Vec<EntityId> {
        let now = chrono::Utc::now().timestamp_millis();
        let stale: Vec<EntityId> = self.routes.iter()
            .filter(|(_, r)| now - r.last_seen > threshold_ms)
            .map(|(id, _)| id.clone())
            .collect();

        for id in &stale {
            self.routes.remove(id);
        }
        stale
    }

    pub fn route_count(&self) -> usize { self.routes.len() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::EntityClass;
    use crate::envelope::*;

    fn mid(n: &str) -> EntityId { EntityId::new(EntityClass::Machine, n) }
    fn aid(n: &str) -> EntityId { EntityId::new(EntityClass::Agent, n) }

    #[test]
    fn test_direct_route() {
        let mut router = Router::new("cell-1");
        router.add_route(mid("m1"), "cell-1", "noise://host1:7100");

        let env = Envelope::new(
            aid("a1"),
            Recipient::Entity(mid("m1")),
            MessageType::Command,
            b"test",
            1,
        );
        let strategy = router.resolve(&env).unwrap();
        assert_eq!(strategy, RoutingStrategy::Direct);
    }

    #[test]
    fn test_relay_route() {
        let mut router = Router::new("cell-1");
        router.add_route(mid("m2"), "cell-2", "noise://host2:7100");
        router.add_gateway("cell-2", "noise://gateway:7200");

        let env = Envelope::new(
            aid("a1"),
            Recipient::Entity(mid("m2")),
            MessageType::Command,
            b"test",
            1,
        );
        let strategy = router.resolve(&env).unwrap();
        assert!(matches!(strategy, RoutingStrategy::Relay { .. }));
    }

    #[test]
    fn test_multicast_route() {
        let mut router = Router::new("cell-1");
        router.register_capabilities(mid("m1"), vec!["machine.move_axis".into()]);
        router.register_capabilities(mid("m2"), vec!["machine.move_axis".into()]);

        let env = Envelope::new(
            aid("a1"),
            Recipient::Capability("machine.move_axis".into()),
            MessageType::Command,
            b"test",
            1,
        );
        let strategy = router.resolve(&env).unwrap();
        assert!(matches!(strategy, RoutingStrategy::Multicast { .. }));

        let targets = router.multicast_targets("machine.move_axis");
        assert_eq!(targets.len(), 2);
    }

    #[test]
    fn test_emergency_route() {
        let router = Router::new("cell-1");
        let env = Envelope::new(
            aid("op"),
            Recipient::Broadcast,
            MessageType::EmergencyStop,
            b"fire",
            1,
        );
        let strategy = router.resolve(&env).unwrap();
        assert_eq!(strategy, RoutingStrategy::Emergency);
    }

    #[test]
    fn test_unknown_entity_fails() {
        let router = Router::new("cell-1");
        let env = Envelope::new(
            aid("a1"),
            Recipient::Entity(mid("unknown")),
            MessageType::Command,
            b"test",
            1,
        );
        assert!(router.resolve(&env).is_err());
    }
}
