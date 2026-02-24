//! Tests for vac-route.

use crate::error::RouteError;
use crate::ring::ConsistentHashRing;
use crate::router::{CellEndpoint, CellRouter, CellStatus};

// ---------------------------------------------------------------------------
// ConsistentHashRing tests
// ---------------------------------------------------------------------------

#[test]
fn test_ring_empty() {
    let ring = ConsistentHashRing::new();
    assert_eq!(ring.cell_count(), 0);
    assert_eq!(ring.vnode_count(), 0);
    assert!(ring.get_node("agent-1").is_none());
}

#[test]
fn test_ring_add_remove_cell() {
    let mut ring = ConsistentHashRing::new();
    assert!(ring.add_cell("cell-1"));
    assert_eq!(ring.cell_count(), 1);
    assert_eq!(ring.vnode_count(), 150);
    assert!(ring.has_cell("cell-1"));

    // Duplicate add returns false
    assert!(!ring.add_cell("cell-1"));
    assert_eq!(ring.cell_count(), 1);

    // Remove
    assert!(ring.remove_cell("cell-1"));
    assert_eq!(ring.cell_count(), 0);
    assert_eq!(ring.vnode_count(), 0);

    // Duplicate remove returns false
    assert!(!ring.remove_cell("cell-1"));
}

#[test]
fn test_ring_deterministic_routing() {
    let mut ring = ConsistentHashRing::new();
    ring.add_cell("cell-1");
    ring.add_cell("cell-2");
    ring.add_cell("cell-3");

    // Same key always routes to same cell
    let cell_a = ring.get_node("agent-abc").unwrap().to_string();
    let cell_b = ring.get_node("agent-abc").unwrap().to_string();
    assert_eq!(cell_a, cell_b);
}

#[test]
fn test_ring_distribution() {
    let mut ring = ConsistentHashRing::new();
    ring.add_cell("cell-1");
    ring.add_cell("cell-2");
    ring.add_cell("cell-3");

    // Route 300 agents and check distribution is roughly even
    let mut counts = std::collections::HashMap::new();
    for i in 0..300 {
        let key = format!("agent-{}", i);
        let cell = ring.get_node(&key).unwrap();
        *counts.entry(cell.to_string()).or_insert(0u32) += 1;
    }

    // Each cell should get roughly 100 agents (allow 30-170 range for randomness)
    for (_cell, count) in &counts {
        assert!(*count > 30, "Cell got too few agents: {}", count);
        assert!(*count < 170, "Cell got too many agents: {}", count);
    }
    assert_eq!(counts.len(), 3);
}

#[test]
fn test_ring_minimal_disruption_on_add() {
    let mut ring = ConsistentHashRing::new();
    ring.add_cell("cell-1");
    ring.add_cell("cell-2");

    // Record routing for 100 agents
    let mut before = std::collections::HashMap::new();
    for i in 0..100 {
        let key = format!("agent-{}", i);
        before.insert(key.clone(), ring.get_node(&key).unwrap().to_string());
    }

    // Add a third cell
    ring.add_cell("cell-3");

    // Count how many agents moved
    let mut moved = 0;
    for i in 0..100 {
        let key = format!("agent-{}", i);
        let after = ring.get_node(&key).unwrap();
        if before[&key] != after {
            moved += 1;
        }
    }

    // With consistent hashing, roughly 1/3 should move (allow generous range)
    assert!(moved < 60, "Too many agents moved: {}/100", moved);
}

#[test]
fn test_ring_get_n_nodes() {
    let mut ring = ConsistentHashRing::new();
    ring.add_cell("cell-1");
    ring.add_cell("cell-2");
    ring.add_cell("cell-3");

    let nodes = ring.get_n_nodes("agent-1", 2);
    assert_eq!(nodes.len(), 2);
    // All returned nodes should be distinct
    assert_ne!(nodes[0], nodes[1]);

    // Requesting more than available returns all
    let all = ring.get_n_nodes("agent-1", 10);
    assert_eq!(all.len(), 3);
}

#[test]
fn test_ring_custom_vnodes() {
    let mut ring = ConsistentHashRing::with_vnodes(10);
    ring.add_cell("cell-1");
    assert_eq!(ring.vnode_count(), 10);
}

// ---------------------------------------------------------------------------
// CellRouter tests
// ---------------------------------------------------------------------------

#[test]
fn test_router_add_and_route() {
    let mut router = CellRouter::new();
    let mut ep1 = CellEndpoint::new("cell-1", "http://cell-1:4222");
    ep1.status = CellStatus::Ready;
    let mut ep2 = CellEndpoint::new("cell-2", "http://cell-2:4222");
    ep2.status = CellStatus::Ready;

    router.add_cell(ep1).unwrap();
    router.add_cell(ep2).unwrap();
    assert_eq!(router.cell_count(), 2);

    let routed = router.route_agent("agent-abc").unwrap();
    assert!(routed.cell_id == "cell-1" || routed.cell_id == "cell-2");
}

#[test]
fn test_router_duplicate_add() {
    let mut router = CellRouter::new();
    let ep = CellEndpoint::new("cell-1", "http://cell-1:4222");
    router.add_cell(ep).unwrap();

    let ep2 = CellEndpoint::new("cell-1", "http://cell-1:9999");
    let result = router.add_cell(ep2);
    assert!(matches!(result.unwrap_err(), RouteError::CellAlreadyRegistered(_)));
}

#[test]
fn test_router_remove_cell() {
    let mut router = CellRouter::new();
    router.add_cell(CellEndpoint::new("cell-1", "http://cell-1:4222")).unwrap();
    router.add_cell(CellEndpoint::new("cell-2", "http://cell-2:4222")).unwrap();

    let removed = router.remove_cell("cell-1").unwrap();
    assert_eq!(removed.cell_id, "cell-1");
    assert_eq!(router.cell_count(), 1);

    // All agents now route to cell-2
    let routed = router.route_agent("any-agent").unwrap();
    assert_eq!(routed.cell_id, "cell-2");
}

#[test]
fn test_router_route_empty() {
    let router = CellRouter::new();
    let result = router.route_agent("agent-1");
    assert!(matches!(result.unwrap_err(), RouteError::NoCells));
}

#[test]
fn test_router_status_and_load() {
    let mut router = CellRouter::new();
    let mut ep = CellEndpoint::new("cell-1", "http://cell-1:4222");
    ep.status = CellStatus::Ready;
    router.add_cell(ep).unwrap();

    router.set_cell_status("cell-1", CellStatus::Degraded).unwrap();
    assert_eq!(router.get_cell("cell-1").unwrap().status, CellStatus::Degraded);

    router.set_cell_load("cell-1", 75).unwrap();
    assert_eq!(router.get_cell("cell-1").unwrap().load, 75);
}

#[test]
fn test_router_available_and_least_loaded() {
    let mut router = CellRouter::new();

    let mut ep1 = CellEndpoint::new("cell-1", "http://cell-1:4222");
    ep1.status = CellStatus::Ready;
    ep1.load = 80;
    router.add_cell(ep1).unwrap();

    let mut ep2 = CellEndpoint::new("cell-2", "http://cell-2:4222");
    ep2.status = CellStatus::Ready;
    ep2.load = 20;
    router.add_cell(ep2).unwrap();

    let mut ep3 = CellEndpoint::new("cell-3", "http://cell-3:4222");
    ep3.status = CellStatus::ShuttingDown;
    ep3.load = 0;
    router.add_cell(ep3).unwrap();

    let available = router.available_cells();
    assert_eq!(available.len(), 2); // cell-3 is ShuttingDown

    let least = router.least_loaded_cell().unwrap();
    assert_eq!(least.cell_id, "cell-2");
    assert_eq!(least.load, 20);
}

#[test]
fn test_router_route_replicas() {
    let mut router = CellRouter::new();
    for i in 1..=3 {
        let mut ep = CellEndpoint::new(&format!("cell-{}", i), &format!("http://cell-{}:4222", i));
        ep.status = CellStatus::Ready;
        router.add_cell(ep).unwrap();
    }

    let replicas = router.route_replicas("some-key", 2);
    assert_eq!(replicas.len(), 2);
    assert_ne!(replicas[0].cell_id, replicas[1].cell_id);
}
