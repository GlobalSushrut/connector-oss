//! Advanced Features — Contract Replay, Proof Verification, Memory Fabric, Cluster Scheduling

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use crate::process::Pid;

// === Part 1: Contract Execution Replay ===

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ReplayEvent {
    ContractLoaded { contract_id: String, version: String },
    StepStarted { step_id: String, step_type: String },
    StepCompleted { step_id: String, duration_ms: u64 },
    StepFailed { step_id: String, error: String },
    MemoryOp { op: String, path: String },
    ToolCall { tool: String },
    StateTransition { from: String, to: String },
    Checkpoint { checkpoint_id: String, state_hash: String },
    ContractCompleted { success: bool },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub seq: u64,
    pub timestamp: i64,
    pub agent_pid: Pid,
    pub session_id: String,
    pub contract_id: String,
    pub event: ReplayEvent,
    pub hash: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplayState { Ready, Running, Paused, Completed, Diverged, Failed }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplaySession {
    pub id: String,
    pub original_session_id: String,
    pub position: u64,
    pub total_entries: u64,
    pub state: ReplayState,
}

#[derive(Debug, Default)]
pub struct ReplayEngine {
    logs: HashMap<String, Vec<AuditLogEntry>>,
    sessions: HashMap<String, ReplaySession>,
}

impl ReplayEngine {
    pub fn new() -> Self { Self::default() }
    
    pub fn load_log(&mut self, session_id: &str, entries: Vec<AuditLogEntry>) {
        self.logs.insert(session_id.into(), entries);
    }
    
    pub fn start_replay(&mut self, original_session_id: &str) -> Result<String, String> {
        let log = self.logs.get(original_session_id).ok_or("No audit log")?;
        let id = format!("replay-{:x}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
        let session = ReplaySession {
            id: id.clone(),
            original_session_id: original_session_id.into(),
            position: 0,
            total_entries: log.len() as u64,
            state: ReplayState::Ready,
        };
        self.sessions.insert(id.clone(), session);
        Ok(id)
    }
    
    pub fn step(&mut self, replay_id: &str) -> Result<Option<&AuditLogEntry>, String> {
        let session = self.sessions.get_mut(replay_id).ok_or("Session not found")?;
        if session.state == ReplayState::Completed { return Ok(None); }
        session.state = ReplayState::Running;
        let log = self.logs.get(&session.original_session_id).ok_or("Log not found")?;
        if session.position >= log.len() as u64 {
            session.state = ReplayState::Completed;
            return Ok(None);
        }
        let entry = &log[session.position as usize];
        session.position += 1;
        if session.position >= session.total_entries { session.state = ReplayState::Completed; }
        Ok(Some(entry))
    }
    
    pub fn get_session(&self, replay_id: &str) -> Option<&ReplaySession> {
        self.sessions.get(replay_id)
    }
}

// === Part 2: Proof Verification API ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_hash: String,
    pub path: Vec<ProofNode>,
    pub root_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofNode {
    pub hash: String,
    pub position: ProofPosition,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofPosition { Left, Right }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub root_hash: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Default)]
pub struct ProofVerifier {
    trusted_roots: HashSet<String>,
}

impl ProofVerifier {
    pub fn new() -> Self { Self::default() }
    pub fn trust_root(&mut self, root: &str) { self.trusted_roots.insert(root.into()); }
    
    pub fn verify_merkle(&self, proof: &MerkleProof) -> VerificationResult {
        let mut current = proof.leaf_hash.clone();
        for node in &proof.path {
            current = match node.position {
                ProofPosition::Left => hash_pair(&node.hash, &current),
                ProofPosition::Right => hash_pair(&current, &node.hash),
            };
        }
        let valid = current == proof.root_hash;
        VerificationResult {
            valid,
            root_hash: if valid { Some(proof.root_hash.clone()) } else { None },
            error: if valid { None } else { Some("Root mismatch".into()) },
        }
    }
    
    pub fn is_trusted(&self, root: &str) -> bool { self.trusted_roots.contains(root) }
}

fn hash_pair(left: &str, right: &str) -> String {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    left.hash(&mut h); right.hash(&mut h);
    format!("{:016x}", h.finish())
}

// === Part 3: Cross-Agent Memory Fabric ===

pub type RegionId = String;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct RegionPermissions { pub read: bool, pub write: bool }

impl RegionPermissions {
    pub fn read_only() -> Self { Self { read: true, write: false } }
    pub fn read_write() -> Self { Self { read: true, write: true } }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedRegion {
    pub id: RegionId,
    pub name: String,
    pub owner: Pid,
    pub size: u64,
    pub attachments: HashMap<Pid, RegionPermissions>,
    pub version: u64,
}

#[derive(Debug, Default)]
pub struct MemoryFabric {
    regions: HashMap<RegionId, SharedRegion>,
    content: HashMap<RegionId, Vec<u8>>,
}

impl MemoryFabric {
    pub fn new() -> Self { Self::default() }
    
    pub fn create_region(&mut self, name: &str, owner: Pid, size: u64) -> RegionId {
        let id = format!("shm-{:x}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis());
        let mut attachments = HashMap::new();
        attachments.insert(owner.clone(), RegionPermissions::read_write());
        let region = SharedRegion { id: id.clone(), name: name.into(), owner, size, attachments, version: 1 };
        self.content.insert(id.clone(), vec![0u8; size as usize]);
        self.regions.insert(id.clone(), region);
        id
    }
    
    pub fn attach(&mut self, region_id: &str, agent: Pid, perms: RegionPermissions) -> Result<(), String> {
        let region = self.regions.get_mut(region_id).ok_or("Region not found")?;
        region.attachments.insert(agent, perms);
        Ok(())
    }
    
    pub fn read(&self, region_id: &str, agent: &Pid, offset: u64, len: u64) -> Result<Vec<u8>, String> {
        let region = self.regions.get(region_id).ok_or("Region not found")?;
        let perms = region.attachments.get(agent).ok_or("Not attached")?;
        if !perms.read { return Err("No read permission".into()); }
        let content = self.content.get(region_id).ok_or("No content")?;
        let start = offset as usize;
        let end = (offset + len) as usize;
        if end > content.len() { return Err("Out of bounds".into()); }
        Ok(content[start..end].to_vec())
    }
    
    pub fn write(&mut self, region_id: &str, agent: &Pid, offset: u64, data: &[u8]) -> Result<(), String> {
        let region = self.regions.get_mut(region_id).ok_or("Region not found")?;
        let perms = region.attachments.get(agent).ok_or("Not attached")?;
        if !perms.write { return Err("No write permission".into()); }
        let content = self.content.get_mut(region_id).ok_or("No content")?;
        let start = offset as usize;
        let end = start + data.len();
        if end > content.len() { return Err("Out of bounds".into()); }
        content[start..end].copy_from_slice(data);
        region.version += 1;
        Ok(())
    }
    
    pub fn get_region(&self, region_id: &str) -> Option<&SharedRegion> { self.regions.get(region_id) }
}

// === Part 4: Cluster-Aware Scheduling ===

pub type NodeId = String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus { Ready, Starting, Draining, Unhealthy, Offline }

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeResources { pub cpu_cores: u32, pub memory_bytes: u64, pub gpu_count: u32 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterNode {
    pub id: NodeId,
    pub address: String,
    pub status: NodeStatus,
    pub resources: NodeResources,
    pub available: NodeResources,
    pub labels: HashMap<String, String>,
    pub agent_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleRequest {
    pub agent_id: String,
    pub resources: NodeResources,
    pub node_selector: HashMap<String, String>,
    pub priority: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleDecision {
    pub node_id: Option<NodeId>,
    pub score: i32,
    pub reason: String,
}

#[derive(Debug, Default)]
pub struct ClusterScheduler {
    nodes: HashMap<NodeId, ClusterNode>,
    placements: HashMap<String, NodeId>,
}

impl ClusterScheduler {
    pub fn new() -> Self { Self::default() }
    
    pub fn register_node(&mut self, node: ClusterNode) { self.nodes.insert(node.id.clone(), node); }
    
    pub fn update_node(&mut self, node_id: &str, status: NodeStatus) -> Result<(), String> {
        let node = self.nodes.get_mut(node_id).ok_or("Node not found")?;
        node.status = status;
        Ok(())
    }
    
    pub fn schedule(&mut self, request: ScheduleRequest) -> ScheduleDecision {
        let mut best: Option<(NodeId, i32)> = None;
        
        for (node_id, node) in &self.nodes {
            if node.status != NodeStatus::Ready { continue; }
            if node.available.cpu_cores < request.resources.cpu_cores { continue; }
            if node.available.memory_bytes < request.resources.memory_bytes { continue; }
            
            let matches = request.node_selector.iter().all(|(k, v)| node.labels.get(k) == Some(v));
            if !matches { continue; }
            
            let score = 100 + node.available.cpu_cores as i32 * 10 - node.agent_count as i32;
            if best.is_none() || score > best.as_ref().unwrap().1 {
                best = Some((node_id.clone(), score));
            }
        }
        
        if let Some((node_id, score)) = best {
            if let Some(node) = self.nodes.get_mut(&node_id) {
                node.available.cpu_cores -= request.resources.cpu_cores;
                node.available.memory_bytes -= request.resources.memory_bytes;
                node.agent_count += 1;
            }
            self.placements.insert(request.agent_id, node_id.clone());
            ScheduleDecision { node_id: Some(node_id), score, reason: "Scheduled".into() }
        } else {
            ScheduleDecision { node_id: None, score: 0, reason: "No suitable node".into() }
        }
    }
    
    pub fn get_placement(&self, agent_id: &str) -> Option<&NodeId> { self.placements.get(agent_id) }
    pub fn list_nodes(&self) -> Vec<&ClusterNode> { self.nodes.values().collect() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replay_engine() {
        let mut engine = ReplayEngine::new();
        let entries = vec![
            AuditLogEntry { seq: 0, timestamp: 0, agent_pid: "pid:001".into(), session_id: "s1".into(),
                contract_id: "c1".into(), event: ReplayEvent::ContractLoaded { contract_id: "c1".into(), version: "1".into() }, hash: "h1".into() },
        ];
        engine.load_log("s1", entries);
        let replay_id = engine.start_replay("s1").unwrap();
        let entry = engine.step(&replay_id).unwrap();
        assert!(entry.is_some());
    }

    #[test]
    fn test_proof_verifier() {
        let verifier = ProofVerifier::new();
        let proof = MerkleProof { leaf_hash: "leaf".into(), path: vec![], root_hash: "leaf".into() };
        let result = verifier.verify_merkle(&proof);
        assert!(result.valid);
    }

    #[test]
    fn test_memory_fabric() {
        let mut fabric = MemoryFabric::new();
        let region_id = fabric.create_region("test", "pid:001".into(), 1024);
        fabric.write(&region_id, &"pid:001".into(), 0, &[1, 2, 3, 4]).unwrap();
        let data = fabric.read(&region_id, &"pid:001".into(), 0, 4).unwrap();
        assert_eq!(data, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_cluster_scheduler() {
        let mut scheduler = ClusterScheduler::new();
        scheduler.register_node(ClusterNode {
            id: "node1".into(), address: "localhost:8080".into(), status: NodeStatus::Ready,
            resources: NodeResources { cpu_cores: 8, memory_bytes: 16_000_000_000, gpu_count: 0 },
            available: NodeResources { cpu_cores: 8, memory_bytes: 16_000_000_000, gpu_count: 0 },
            labels: HashMap::new(), agent_count: 0,
        });
        let decision = scheduler.schedule(ScheduleRequest {
            agent_id: "agent1".into(),
            resources: NodeResources { cpu_cores: 2, memory_bytes: 4_000_000_000, gpu_count: 0 },
            node_selector: HashMap::new(), priority: 0,
        });
        assert!(decision.node_id.is_some());
    }
}
