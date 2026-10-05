//! # Knowledge Transfer Graph (KTG)
//!
//! Tracks and facilitates knowledge flow between agents.
//!
//! ## Graph Structure
//! - **Nodes**: Agents with capability profiles derived from task history
//! - **Directed edges**: Transfer relationships (A → B = A has given knowledge to B)
//! - **Edge weight**: `similarity * acceptance_rate * log(1+count) * recency_decay`
//!
//! ## Persistence
//! In-memory `KnowledgeGraph` (Arc<Mutex<...>>), persisted to two engine_store keys:
//! `"ktg_nodes"` and `"ktg_edges"` as JSON maps on every write.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};

use crate::state::SharedState;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

// ═══════════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KtgNode {
    pub agent_pid: String,
    pub agent_name: String,
    /// Normalised capability vector: domain → proficiency [0,1]
    pub capability_vector: HashMap<String, f64>,
    /// Accumulated domain tags
    pub domain_tags: Vec<String>,
    pub llm_calls: u64,
    pub total_cost_usd: f64,
    pub last_active_ms: u64,
    pub created_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KtgEdge {
    pub from_pid: String,
    pub to_pid: String,
    pub transfer_count: u64,
    pub accepted_count: u64,
    pub tokens_transferred: u64,
    pub similarity_score: f64,
    pub last_transfer_ms: u64,
    /// Composite weight: similarity * acceptance * log(1+count) * recency_decay
    pub weight: f64,
}

impl KtgEdge {
    pub fn recompute_weight(&mut self) {
        let acceptance = if self.transfer_count > 0 {
            self.accepted_count as f64 / self.transfer_count as f64
        } else {
            0.5
        };
        let freq = (1.0 + self.transfer_count as f64).ln();
        let age_d = (now_ms().saturating_sub(self.last_transfer_ms)) as f64 / 86_400_000.0;
        let recency = (-age_d / 30.0).exp();
        self.weight = self.similarity_score * acceptance * freq * recency;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRecord {
    pub transfer_id: String,
    pub from_pid: String,
    pub to_pid: String,
    pub content_summary: String,
    pub tokens: u64,
    pub similarity: f64,
    pub timestamp_ms: u64,
    pub accepted: bool,
}

// ═══════════════════════════════════════════════════════════════
// In-memory Graph
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GraphState {
    pub nodes: HashMap<String, KtgNode>, // pid → node
    pub edges: HashMap<String, HashMap<String, KtgEdge>>, // from → to → edge
    #[serde(skip)]
    pub transfers: VecDeque<TransferRecord>, // rolling log (500 max)
}

#[derive(Clone)]
pub struct KnowledgeGraph {
    inner: Arc<Mutex<GraphState>>,
}

impl KnowledgeGraph {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(GraphState::default())),
        }
    }

    // ── Cosine similarity ───────────────────────────────────────
    fn similarity(a: &HashMap<String, f64>, b: &HashMap<String, f64>) -> f64 {
        let dot: f64 = a
            .iter()
            .filter_map(|(k, va)| b.get(k).map(|vb| va * vb))
            .sum();
        let na: f64 = a.values().map(|v| v * v).sum::<f64>().sqrt();
        let nb: f64 = b.values().map(|v| v * v).sum::<f64>().sqrt();
        if na == 0.0 || nb == 0.0 {
            return 0.0;
        }
        (dot / (na * nb)).min(1.0).max(0.0)
    }

    fn tags_to_vector(tags: &[String]) -> HashMap<String, f64> {
        let mut freq: HashMap<String, u32> = HashMap::new();
        for t in tags {
            *freq.entry(t.clone()).or_insert(0) += 1;
        }
        let max = freq.values().cloned().max().unwrap_or(1) as f64;
        freq.into_iter().map(|(k, v)| (k, v as f64 / max)).collect()
    }

    // ── Node upsert ─────────────────────────────────────────────
    pub fn update_node(&self, agent_pid: &str, agent_name: &str, tags: Vec<String>, cost_usd: f64) {
        let mut g = self.inner.lock().unwrap();
        let node = g
            .nodes
            .entry(agent_pid.to_string())
            .or_insert_with(|| KtgNode {
                agent_pid: agent_pid.to_string(),
                agent_name: agent_name.to_string(),
                capability_vector: HashMap::new(),
                domain_tags: vec![],
                llm_calls: 0,
                total_cost_usd: 0.0,
                last_active_ms: 0,
                created_at_ms: now_ms(),
            });
        for tag in &tags {
            if !node.domain_tags.contains(tag) {
                node.domain_tags.push(tag.clone());
            }
        }
        node.capability_vector = Self::tags_to_vector(&node.domain_tags);
        node.llm_calls += 1;
        node.total_cost_usd += cost_usd;
        node.last_active_ms = now_ms();
        node.agent_name = agent_name.to_string();
    }

    // ── Transfer ────────────────────────────────────────────────
    /// Record a knowledge transfer from `from_pid` → `to_pid`.
    /// Returns the similarity score between the two agents.
    pub fn record_transfer(
        &self,
        from_pid: &str,
        to_pid: &str,
        content_summary: &str,
        tokens: u64,
        accepted: bool,
    ) -> f64 {
        let mut g = self.inner.lock().unwrap();
        let sim = {
            let fv = g
                .nodes
                .get(from_pid)
                .map(|n| n.capability_vector.clone())
                .unwrap_or_default();
            let tv = g
                .nodes
                .get(to_pid)
                .map(|n| n.capability_vector.clone())
                .unwrap_or_default();
            Self::similarity(&fv, &tv)
        };
        // Update edge
        let edge = g
            .edges
            .entry(from_pid.to_string())
            .or_default()
            .entry(to_pid.to_string())
            .or_insert_with(|| KtgEdge {
                from_pid: from_pid.to_string(),
                to_pid: to_pid.to_string(),
                transfer_count: 0,
                accepted_count: 0,
                tokens_transferred: 0,
                similarity_score: sim,
                last_transfer_ms: 0,
                weight: 0.0,
            });
        edge.transfer_count += 1;
        if accepted {
            edge.accepted_count += 1;
        }
        edge.tokens_transferred += tokens;
        edge.last_transfer_ms = now_ms();
        edge.similarity_score = edge.similarity_score * 0.8 + sim * 0.2; // EMA
        edge.recompute_weight();
        // Record in transfer log
        let rec = TransferRecord {
            transfer_id: format!("ktf_{:x}", now_ms()),
            from_pid: from_pid.to_string(),
            to_pid: to_pid.to_string(),
            content_summary: content_summary.chars().take(200).collect(),
            tokens,
            similarity: sim,
            timestamp_ms: now_ms(),
            accepted,
        };
        if g.transfers.len() >= 500 {
            g.transfers.pop_front();
        }
        g.transfers.push_back(rec);
        sim
    }

    // ── Queries ─────────────────────────────────────────────────
    pub fn find_similar(&self, agent_pid: &str, limit: usize) -> Vec<(String, f64)> {
        let g = self.inner.lock().unwrap();
        let src_vec = match g.nodes.get(agent_pid) {
            Some(n) => n.capability_vector.clone(),
            None => return vec![],
        };
        let mut scored: Vec<(String, f64)> = g
            .nodes
            .iter()
            .filter(|(pid, _)| pid.as_str() != agent_pid)
            .map(|(pid, n)| {
                (
                    pid.clone(),
                    Self::similarity(&src_vec, &n.capability_vector),
                )
            })
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(limit);
        scored
    }

    pub fn all_nodes(&self) -> Vec<KtgNode> {
        self.inner.lock().unwrap().nodes.values().cloned().collect()
    }

    pub fn all_edges(&self) -> Vec<KtgEdge> {
        self.inner
            .lock()
            .unwrap()
            .edges
            .values()
            .flat_map(|m| m.values().cloned())
            .collect()
    }

    pub fn recent_transfers(&self, agent_pid: Option<&str>, limit: usize) -> Vec<TransferRecord> {
        let g = self.inner.lock().unwrap();
        let mut v: Vec<TransferRecord> = g
            .transfers
            .iter()
            .filter(|r| {
                agent_pid
                    .map(|p| r.from_pid == p || r.to_pid == p)
                    .unwrap_or(true)
            })
            .cloned()
            .collect();
        v.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));
        v.truncate(limit);
        v
    }

    pub fn node(&self, pid: &str) -> Option<KtgNode> {
        self.inner.lock().unwrap().nodes.get(pid).cloned()
    }

    pub fn edges_for(&self, pid: &str) -> Vec<KtgEdge> {
        let g = self.inner.lock().unwrap();
        let mut result = vec![];
        if let Some(m) = g.edges.get(pid) {
            result.extend(m.values().cloned());
        }
        for (_, m) in &g.edges {
            if let Some(e) = m.get(pid) {
                result.push(e.clone());
            }
        }
        result
    }

    /// Auto-transfer: push context from `from_pid` to all sufficiently-similar agents.
    /// Returns list of agent PIDs that received a transfer.
    pub fn auto_transfer(
        &self,
        from_pid: &str,
        content_summary: &str,
        tokens: u64,
        threshold: f64,
    ) -> Vec<String> {
        let similar = self.find_similar(from_pid, 10);
        let mut recipients = vec![];
        for (pid, sim) in similar {
            if sim >= threshold {
                self.record_transfer(from_pid, &pid, content_summary, tokens, true);
                recipients.push(pid);
            }
        }
        recipients
    }
}

// ═══════════════════════════════════════════════════════════════
// REST API Handlers
// ═══════════════════════════════════════════════════════════════

pub async fn get_graph(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let ktg = match &state.knowledge_graph {
        Some(g) => g,
        None => return Json(serde_json::json!({"nodes":[],"edges":[]})),
    };
    let nodes = ktg.all_nodes();
    let edges = ktg.all_edges();
    Json(serde_json::json!({
        "nodes":       nodes,
        "edges":       edges,
        "node_count":  nodes.len(),
        "edge_count":  edges.len(),
    }))
}

pub async fn get_agent_node(
    State(state): State<SharedState>,
    axum::extract::Path(pid): axum::extract::Path<String>,
) -> Json<serde_json::Value> {
    let ktg = match &state.knowledge_graph {
        Some(g) => g,
        None => return Json(serde_json::json!({"error": "KTG not initialised"})),
    };
    let node = ktg.node(&pid);
    let similar = ktg.find_similar(&pid, 5);
    let transfers = ktg.recent_transfers(Some(&pid), 20);
    let edges = ktg.edges_for(&pid);
    Json(serde_json::json!({
        "node": node,
        "similar_agents": similar.iter().map(|(p, s)| serde_json::json!({"agent_pid": p, "similarity": s})).collect::<Vec<_>>(),
        "edges": edges,
        "recent_transfers": transfers,
    }))
}

pub async fn get_transfers(State(state): State<SharedState>) -> Json<serde_json::Value> {
    let ktg = match &state.knowledge_graph {
        Some(g) => g,
        None => return Json(serde_json::json!({"transfers":[]})),
    };
    let transfers = ktg.recent_transfers(None, 50);
    Json(serde_json::json!({"transfers": transfers, "count": transfers.len()}))
}

#[derive(Deserialize)]
pub struct ManualTransferRequest {
    pub from_pid: String,
    pub to_pid: String,
    pub content_summary: String,
    #[serde(default)]
    pub tokens: u64,
}

pub async fn trigger_transfer(
    State(state): State<SharedState>,
    Json(req): Json<ManualTransferRequest>,
) -> Json<serde_json::Value> {
    let ktg = match &state.knowledge_graph {
        Some(g) => g,
        None => return Json(serde_json::json!({"error": "KTG not initialised"})),
    };
    let sim = ktg.record_transfer(
        &req.from_pid,
        &req.to_pid,
        &req.content_summary,
        req.tokens,
        true,
    );
    Json(serde_json::json!({"ok": true, "similarity": sim, "from": req.from_pid, "to": req.to_pid}))
}
