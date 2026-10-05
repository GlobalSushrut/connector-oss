//! # Continuity Fabric
//!
//! Cognition-stability layer that stores reasoning graphs, span lineage,
//! page chains, fork/merge paths, and summary compression graphs.
//!
//! Without this layer, long-term cognition remains fragile — the system cannot
//! reconstruct why something was chosen, what alternatives existed, where
//! branching occurred, or what was summarized later.
//!
//! ## Industry Reference
//!
//! - OpenTelemetry: distributed tracing, spans, trace context
//! - Git: DAG of commits with branching and merging

use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use super::types::*;

// =============================================================================
// ContinuityNode — a node in the reasoning graph
// =============================================================================

/// A node in the continuity graph representing a reasoning step, memory
/// reference, page, summary, decision, merge, or projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuityNode {
    pub node_id: String,
    pub node_type: NodeType,
    pub trace_id: String,
    pub container_id: String,
    pub parent_id: Option<String>,
    pub object_ref: Option<String>,
    pub vector_ref: Option<String>,
    pub summary_ref: Option<String>,
    pub span_type: Option<SpanType>,
    pub timestamp: i64,
    pub policy_class: String,
    pub metadata: HashMap<String, String>,
}

// =============================================================================
// ContinuityEdge — a directed edge in the reasoning graph
// =============================================================================

/// A directed edge connecting two continuity nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContinuityEdge {
    pub from_id: String,
    pub to_id: String,
    pub edge_type: EdgeType,
    pub weight: f64,
    pub created_at: i64,
}

// =============================================================================
// ContinuityGraph — the full reasoning graph
// =============================================================================

/// DAG-structured reasoning graph for a container or trace.
///
/// Provides traversal, lineage reconstruction, and subgraph extraction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContinuityGraph {
    nodes: HashMap<String, ContinuityNode>,
    /// Forward adjacency: node_id → outgoing edges
    forward: HashMap<String, Vec<ContinuityEdge>>,
    /// Reverse adjacency: node_id → incoming edges
    reverse: HashMap<String, Vec<ContinuityEdge>>,
    /// Trace index: trace_id → node_ids (ordered by timestamp)
    traces: HashMap<String, Vec<String>>,
}

impl ContinuityGraph {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a node to the graph.
    pub fn add_node(&mut self, node: ContinuityNode) {
        let nid = node.node_id.clone();
        let tid = node.trace_id.clone();

        self.traces.entry(tid).or_default().push(nid.clone());
        self.nodes.insert(nid, node);
    }

    /// Add an edge to the graph.
    pub fn add_edge(&mut self, edge: ContinuityEdge) {
        self.reverse
            .entry(edge.to_id.clone())
            .or_default()
            .push(edge.clone());
        self.forward
            .entry(edge.from_id.clone())
            .or_default()
            .push(edge);
    }

    /// Get a node by ID.
    pub fn get_node(&self, node_id: &str) -> Option<&ContinuityNode> {
        self.nodes.get(node_id)
    }

    /// Get all nodes for a trace, sorted by timestamp.
    pub fn trace_nodes(&self, trace_id: &str) -> Vec<&ContinuityNode> {
        let mut nodes: Vec<&ContinuityNode> = self.traces
            .get(trace_id)
            .map(|ids| ids.iter().filter_map(|id| self.nodes.get(id)).collect())
            .unwrap_or_default();
        nodes.sort_by_key(|n| n.timestamp);
        nodes
    }

    /// Get outgoing edges from a node.
    pub fn outgoing(&self, node_id: &str) -> &[ContinuityEdge] {
        self.forward.get(node_id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get incoming edges to a node.
    pub fn incoming(&self, node_id: &str) -> &[ContinuityEdge] {
        self.reverse.get(node_id).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Get the full lineage (ancestors) of a node by following reverse edges.
    pub fn lineage(&self, node_id: &str, max_depth: usize) -> Vec<&ContinuityNode> {
        let mut result = Vec::new();
        let mut frontier = vec![node_id.to_string()];
        let mut visited = std::collections::HashSet::new();
        visited.insert(node_id.to_string());

        for _ in 0..max_depth {
            let mut next = Vec::new();
            for nid in &frontier {
                for edge in self.incoming(nid) {
                    if visited.insert(edge.from_id.clone()) {
                        if let Some(node) = self.nodes.get(&edge.from_id) {
                            result.push(node);
                        }
                        next.push(edge.from_id.clone());
                    }
                }
            }
            if next.is_empty() { break; }
            frontier = next;
        }
        result
    }

    /// Get descendants of a node by following forward edges.
    pub fn descendants(&self, node_id: &str, max_depth: usize) -> Vec<&ContinuityNode> {
        let mut result = Vec::new();
        let mut frontier = vec![node_id.to_string()];
        let mut visited = std::collections::HashSet::new();
        visited.insert(node_id.to_string());

        for _ in 0..max_depth {
            let mut next = Vec::new();
            for nid in &frontier {
                for edge in self.outgoing(nid) {
                    if visited.insert(edge.to_id.clone()) {
                        if let Some(node) = self.nodes.get(&edge.to_id) {
                            result.push(node);
                        }
                        next.push(edge.to_id.clone());
                    }
                }
            }
            if next.is_empty() { break; }
            frontier = next;
        }
        result
    }

    /// Find all root nodes (nodes with no incoming edges) for a trace.
    pub fn trace_roots(&self, trace_id: &str) -> Vec<&ContinuityNode> {
        self.trace_nodes(trace_id)
            .into_iter()
            .filter(|n| self.incoming(&n.node_id).is_empty())
            .collect()
    }

    /// Find all leaf nodes (nodes with no outgoing edges) for a trace.
    pub fn trace_leaves(&self, trace_id: &str) -> Vec<&ContinuityNode> {
        self.trace_nodes(trace_id)
            .into_iter()
            .filter(|n| self.outgoing(&n.node_id).is_empty())
            .collect()
    }

    /// Find fork points: nodes with >1 outgoing edges.
    pub fn fork_points(&self, trace_id: &str) -> Vec<&ContinuityNode> {
        self.trace_nodes(trace_id)
            .into_iter()
            .filter(|n| self.outgoing(&n.node_id).len() > 1)
            .collect()
    }

    /// Find merge points: nodes with >1 incoming edges.
    pub fn merge_points(&self, trace_id: &str) -> Vec<&ContinuityNode> {
        self.trace_nodes(trace_id)
            .into_iter()
            .filter(|n| self.incoming(&n.node_id).len() > 1)
            .collect()
    }

    /// Extract a subgraph containing only nodes and edges for a specific trace.
    pub fn subgraph(&self, trace_id: &str) -> ContinuityGraph {
        let mut sub = ContinuityGraph::new();
        let node_ids: std::collections::HashSet<String> = self.traces
            .get(trace_id)
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .collect();

        for nid in &node_ids {
            if let Some(node) = self.nodes.get(nid) {
                sub.add_node(node.clone());
            }
            for edge in self.outgoing(nid) {
                if node_ids.contains(&edge.to_id) {
                    sub.add_edge(edge.clone());
                }
            }
        }
        sub
    }

    /// Remove a node and all its edges.
    pub fn remove_node(&mut self, node_id: &str) {
        self.nodes.remove(node_id);
        self.forward.remove(node_id);
        self.reverse.remove(node_id);
        for edges in self.forward.values_mut() {
            edges.retain(|e| e.to_id != node_id);
        }
        for edges in self.reverse.values_mut() {
            edges.retain(|e| e.from_id != node_id);
        }
        for ids in self.traces.values_mut() {
            ids.retain(|id| id != node_id);
        }
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    pub fn edge_count(&self) -> usize {
        self.forward.values().map(|v| v.len()).sum()
    }

    pub fn trace_count(&self) -> usize {
        self.traces.len()
    }
}

// =============================================================================
// PageChain — stable paginated retrieval results
// =============================================================================

/// A frozen, stable paginated result set for retrieval queries.
///
/// Never paginate raw vector results directly. Instead freeze a retrieval
/// snapshot and paginate through a PageChain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageChain {
    pub chain_id: String,
    pub query_fingerprint: String,
    pub pages: Vec<Page>,
    pub created_at: i64,
    pub total_results: u64,
}

/// A single page in a PageChain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page {
    pub page_id: String,
    pub chain_id: String,
    pub page_number: u32,
    pub result_refs: Vec<String>,
    pub ranking_version: u64,
    pub continuity_checksum: String,
    pub prev_page: Option<String>,
    pub next_page: Option<String>,
}

impl PageChain {
    /// Create a new page chain from a list of memory IDs.
    pub fn from_results(
        query_fingerprint: String,
        memory_ids: Vec<String>,
        page_size: usize,
    ) -> Self {
        let chain_id = generate_id("pgchain");
        let total = memory_ids.len() as u64;
        let chunks: Vec<Vec<String>> = memory_ids
            .chunks(page_size.max(1))
            .map(|c| c.to_vec())
            .collect();

        let mut pages: Vec<Page> = chunks.iter().enumerate().map(|(i, chunk)| {
            let page_id = format!("{}:p{}", chain_id, i);
            Page {
                page_id: page_id.clone(),
                chain_id: chain_id.clone(),
                page_number: i as u32,
                result_refs: chunk.clone(),
                ranking_version: 1,
                continuity_checksum: sha2_hex(
                    chunk.join(",").as_bytes()
                ),
                prev_page: None,
                next_page: None,
            }
        }).collect();

        // Link pages
        for i in 0..pages.len() {
            if i > 0 {
                let prev_id = pages[i - 1].page_id.clone();
                pages[i].prev_page = Some(prev_id);
            }
            if i + 1 < pages.len() {
                let next_id = pages[i + 1].page_id.clone();
                pages[i].next_page = Some(next_id);
            }
        }

        Self {
            chain_id,
            query_fingerprint,
            pages,
            created_at: now_ms(),
            total_results: total,
        }
    }

    /// Get a page by number.
    pub fn get_page(&self, page_number: u32) -> Option<&Page> {
        self.pages.get(page_number as usize)
    }

    /// Total page count.
    pub fn page_count(&self) -> usize {
        self.pages.len()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_node(id: &str, trace: &str, node_type: NodeType, ts: i64) -> ContinuityNode {
        ContinuityNode {
            node_id: id.to_string(),
            node_type,
            trace_id: trace.to_string(),
            container_id: "cont:test".to_string(),
            parent_id: None,
            object_ref: None,
            vector_ref: None,
            summary_ref: None,
            span_type: None,
            timestamp: ts,
            policy_class: "default".to_string(),
            metadata: HashMap::new(),
        }
    }

    fn make_edge(from: &str, to: &str, edge_type: EdgeType) -> ContinuityEdge {
        ContinuityEdge {
            from_id: from.to_string(),
            to_id: to.to_string(),
            edge_type,
            weight: 1.0,
            created_at: now_ms(),
        }
    }

    #[test]
    fn test_graph_add_and_traverse() {
        let mut g = ContinuityGraph::new();
        g.add_node(make_node("n1", "t1", NodeType::TraceRoot, 1000));
        g.add_node(make_node("n2", "t1", NodeType::ThoughtSpan, 2000));
        g.add_node(make_node("n3", "t1", NodeType::DecisionNode, 3000));
        g.add_edge(make_edge("n1", "n2", EdgeType::Next));
        g.add_edge(make_edge("n2", "n3", EdgeType::Next));

        assert_eq!(g.node_count(), 3);
        assert_eq!(g.edge_count(), 2);

        let trace = g.trace_nodes("t1");
        assert_eq!(trace.len(), 3);
        assert_eq!(trace[0].node_id, "n1"); // sorted by timestamp
    }

    #[test]
    fn test_graph_lineage() {
        let mut g = ContinuityGraph::new();
        g.add_node(make_node("root", "t1", NodeType::TraceRoot, 1000));
        g.add_node(make_node("mid", "t1", NodeType::ThoughtSpan, 2000));
        g.add_node(make_node("leaf", "t1", NodeType::DecisionNode, 3000));
        g.add_edge(make_edge("root", "mid", EdgeType::Next));
        g.add_edge(make_edge("mid", "leaf", EdgeType::Next));

        let ancestors = g.lineage("leaf", 10);
        assert_eq!(ancestors.len(), 2);

        let descendants = g.descendants("root", 10);
        assert_eq!(descendants.len(), 2);
    }

    #[test]
    fn test_graph_roots_and_leaves() {
        let mut g = ContinuityGraph::new();
        g.add_node(make_node("r", "t1", NodeType::TraceRoot, 1000));
        g.add_node(make_node("m", "t1", NodeType::ThoughtSpan, 2000));
        g.add_node(make_node("l", "t1", NodeType::DecisionNode, 3000));
        g.add_edge(make_edge("r", "m", EdgeType::Next));
        g.add_edge(make_edge("m", "l", EdgeType::Next));

        let roots = g.trace_roots("t1");
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].node_id, "r");

        let leaves = g.trace_leaves("t1");
        assert_eq!(leaves.len(), 1);
        assert_eq!(leaves[0].node_id, "l");
    }

    #[test]
    fn test_graph_fork_merge() {
        let mut g = ContinuityGraph::new();
        g.add_node(make_node("root", "t1", NodeType::TraceRoot, 1000));
        g.add_node(make_node("b1", "t1", NodeType::ThoughtSpan, 2000));
        g.add_node(make_node("b2", "t1", NodeType::ThoughtSpan, 2001));
        g.add_node(make_node("merge", "t1", NodeType::MergeNode, 3000));
        g.add_edge(make_edge("root", "b1", EdgeType::ForksTo));
        g.add_edge(make_edge("root", "b2", EdgeType::ForksTo));
        g.add_edge(make_edge("b1", "merge", EdgeType::MergesInto));
        g.add_edge(make_edge("b2", "merge", EdgeType::MergesInto));

        let forks = g.fork_points("t1");
        assert_eq!(forks.len(), 1);
        assert_eq!(forks[0].node_id, "root");

        let merges = g.merge_points("t1");
        assert_eq!(merges.len(), 1);
        assert_eq!(merges[0].node_id, "merge");
    }

    #[test]
    fn test_graph_subgraph() {
        let mut g = ContinuityGraph::new();
        g.add_node(make_node("a1", "t1", NodeType::TraceRoot, 1000));
        g.add_node(make_node("a2", "t1", NodeType::ThoughtSpan, 2000));
        g.add_node(make_node("b1", "t2", NodeType::TraceRoot, 3000));
        g.add_edge(make_edge("a1", "a2", EdgeType::Next));

        let sub = g.subgraph("t1");
        assert_eq!(sub.node_count(), 2);
        assert_eq!(sub.edge_count(), 1);
    }

    #[test]
    fn test_graph_remove_node() {
        let mut g = ContinuityGraph::new();
        g.add_node(make_node("a", "t1", NodeType::TraceRoot, 1000));
        g.add_node(make_node("b", "t1", NodeType::ThoughtSpan, 2000));
        g.add_edge(make_edge("a", "b", EdgeType::Next));
        assert_eq!(g.node_count(), 2);

        g.remove_node("b");
        assert_eq!(g.node_count(), 1);
        assert_eq!(g.outgoing("a").len(), 0);
    }

    #[test]
    fn test_page_chain_creation() {
        let ids: Vec<String> = (0..25).map(|i| format!("m:{}", i)).collect();
        let chain = PageChain::from_results("query:test".to_string(), ids, 10);

        assert_eq!(chain.total_results, 25);
        assert_eq!(chain.page_count(), 3);

        let p0 = chain.get_page(0).unwrap();
        assert_eq!(p0.result_refs.len(), 10);
        assert!(p0.prev_page.is_none());
        assert!(p0.next_page.is_some());

        let p1 = chain.get_page(1).unwrap();
        assert_eq!(p1.result_refs.len(), 10);
        assert!(p1.prev_page.is_some());
        assert!(p1.next_page.is_some());

        let p2 = chain.get_page(2).unwrap();
        assert_eq!(p2.result_refs.len(), 5);
        assert!(p2.prev_page.is_some());
        assert!(p2.next_page.is_none());
    }

    #[test]
    fn test_page_chain_empty() {
        let chain = PageChain::from_results("q".to_string(), vec![], 10);
        assert_eq!(chain.total_results, 0);
        assert_eq!(chain.page_count(), 0);
    }

    #[test]
    fn test_page_chain_single_page() {
        let ids: Vec<String> = (0..3).map(|i| format!("m:{}", i)).collect();
        let chain = PageChain::from_results("q".to_string(), ids, 10);
        assert_eq!(chain.page_count(), 1);

        let p = chain.get_page(0).unwrap();
        assert!(p.prev_page.is_none());
        assert!(p.next_page.is_none());
    }

    #[test]
    fn test_page_continuity_checksum() {
        let ids = vec!["a".to_string(), "b".to_string()];
        let chain = PageChain::from_results("q".to_string(), ids, 10);
        let p = chain.get_page(0).unwrap();
        assert!(!p.continuity_checksum.is_empty());
        assert_eq!(p.continuity_checksum.len(), 64); // SHA-256 hex
    }
}
