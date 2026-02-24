//! Memory Coordinator — app-layer bridge to the VAC Memory Kernel.
//!
//! Provides stable, high-level memory operations:
//! - Sessions, tiers, sealing, search, recall
//! - Knowledge graph (KnotEngine) coordination
//! - Interference detection (contradictions, state vectors)
//! - Access control (grant, revoke)

use vac_core::kernel::{MemoryKernel, SyscallRequest, SyscallPayload, SyscallValue};
use vac_core::types::*;
use vac_core::interference::{self, StateVector, InterferenceEdge};
use vac_core::knot::{KnotEngine, KnotQuery, FusedResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ═══════════════════════════════════════════════════════════════
// PacketSummary — lightweight search result
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSummary {
    pub cid: String,
    pub text: String,
    pub packet_type: String,
    pub timestamp: i64,
    pub entities: Vec<String>,
    pub tags: Vec<String>,
    pub namespace: Option<String>,
    pub session_id: Option<String>,
    pub tier: String,
}

impl PacketSummary {
    pub fn from_packet(p: &MemPacket) -> Self {
        let text = p.content.payload.get("text")
            .and_then(|v| v.as_str())
            .unwrap_or("[binary]")
            .to_string();
        let preview = if text.len() > 200 { format!("{}...", &text[..200]) } else { text };
        Self {
            cid: p.index.packet_cid.to_string(),
            text: preview,
            packet_type: format!("{:?}", p.content.packet_type),
            timestamp: p.index.ts,
            entities: p.content.entities.clone(),
            tags: p.content.tags.clone(),
            namespace: p.namespace.clone(),
            session_id: p.session_id.clone(),
            tier: format!("{:?}", p.tier),
        }
    }
}

// ═══════════════════════════════════════════════════════════════
// MemoryCoordinator — high-level kernel operations
// ═══════════════════════════════════════════════════════════════

pub struct MemoryCoordinator;

impl MemoryCoordinator {
    /// Create session. Returns session_id.
    pub fn create_session(k: &mut MemoryKernel, pid: &str, label: Option<&str>) -> Result<String, String> {
        let sid = format!("session:{}", chrono::Utc::now().timestamp_millis());
        let r = k.dispatch(SyscallRequest {
            agent_pid: pid.to_string(),
            operation: MemoryKernelOp::SessionCreate,
            payload: SyscallPayload::SessionCreate {
                session_id: sid.clone(),
                label: label.map(|s| s.to_string()),
                parent_session_id: None,
            },
            reason: Some("create session".into()), vakya_id: None,
        });
        match r.outcome {
            OpOutcome::Success => Ok(sid),
            _ => Err(format!("{:?}: {}", r.outcome, r.audit_entry.error.unwrap_or_default())),
        }
    }

    /// Close session.
    pub fn close_session(k: &mut MemoryKernel, pid: &str, sid: &str) -> Result<(), String> {
        let r = k.dispatch(SyscallRequest {
            agent_pid: pid.to_string(),
            operation: MemoryKernelOp::SessionClose,
            payload: SyscallPayload::SessionClose {
                session_id: sid.to_string(),
            },
            reason: Some("close session".into()), vakya_id: None,
        });
        if r.outcome == OpOutcome::Success { Ok(()) }
        else { Err(format!("{:?}: {}", r.outcome, r.audit_entry.error.unwrap_or_default())) }
    }

    /// Write packet with entities and tags. Returns CID.
    pub fn write(
        k: &mut MemoryKernel, pid: &str, content: &str, user: &str, pipeline: &str,
        ptype: PacketType, session_id: Option<&str>, entities: Vec<String>, tags: Vec<String>,
    ) -> Result<cid::Cid, String> {
        let mut pkt = MemPacket::new(
            ptype, serde_json::json!({"text": content}), cid::Cid::default(),
            user.to_string(), pipeline.to_string(),
            Source { kind: SourceKind::User, principal_id: user.to_string() },
            chrono::Utc::now().timestamp_millis(),
        );
        if let Some(sid) = session_id { pkt.session_id = Some(sid.to_string()); }
        pkt.content.entities = entities;
        pkt.content.tags = tags;

        let r = k.dispatch(SyscallRequest {
            agent_pid: pid.to_string(),
            operation: MemoryKernelOp::MemWrite,
            payload: SyscallPayload::MemWrite { packet: pkt },
            reason: None, vakya_id: None,
        });
        match r.value {
            SyscallValue::Cid(c) => Ok(c),
            SyscallValue::Error(e) => Err(e),
            _ => Err(format!("{:?}", r.outcome)),
        }
    }

    /// Read packet by CID. Returns text content.
    pub fn recall(k: &mut MemoryKernel, pid: &str, cid: &cid::Cid) -> Result<String, String> {
        let r = k.dispatch(SyscallRequest {
            agent_pid: pid.to_string(),
            operation: MemoryKernelOp::MemRead,
            payload: SyscallPayload::MemRead { packet_cid: cid.clone() },
            reason: Some("recall".into()), vakya_id: None,
        });
        match (r.outcome.clone(), r.value) {
            (OpOutcome::Success, SyscallValue::Packet(p)) => {
                Ok(p.content.payload.get("text").and_then(|v| v.as_str()).unwrap_or("[binary]").to_string())
            }
            (OpOutcome::Denied, _) => Err(format!("DENIED: {}", r.audit_entry.error.unwrap_or_default())),
            _ => Err(format!("{:?}: {}", r.outcome, r.audit_entry.error.unwrap_or_default())),
        }
    }

    /// Search packets in namespace.
    pub fn search_namespace(k: &MemoryKernel, ns: &str, limit: usize) -> Vec<PacketSummary> {
        k.packets_in_namespace(ns).iter().take(limit).map(|p| PacketSummary::from_packet(p)).collect()
    }

    /// Search packets in session.
    pub fn search_session(k: &MemoryKernel, sid: &str, limit: usize) -> Vec<PacketSummary> {
        k.packets_in_session(sid).iter().take(limit).map(|p| PacketSummary::from_packet(p)).collect()
    }

    /// Promote packet to higher tier (e.g. Warm → Hot).
    pub fn promote(k: &mut MemoryKernel, pid: &str, cid: &cid::Cid) -> Result<(), String> {
        let r = k.dispatch(SyscallRequest {
            agent_pid: pid.to_string(), operation: MemoryKernelOp::MemPromote,
            payload: SyscallPayload::TierChange { packet_cid: cid.clone(), new_tier: MemoryTier::Hot },
            reason: Some("promote".into()), vakya_id: None,
        });
        if r.outcome == OpOutcome::Success { Ok(()) } else { Err(format!("{:?}", r.outcome)) }
    }

    /// Demote packet to lower tier (e.g. Hot → Warm).
    pub fn demote(k: &mut MemoryKernel, pid: &str, cid: &cid::Cid) -> Result<(), String> {
        let r = k.dispatch(SyscallRequest {
            agent_pid: pid.to_string(), operation: MemoryKernelOp::MemDemote,
            payload: SyscallPayload::TierChange { packet_cid: cid.clone(), new_tier: MemoryTier::Cold },
            reason: Some("demote".into()), vakya_id: None,
        });
        if r.outcome == OpOutcome::Success { Ok(()) } else { Err(format!("{:?}", r.outcome)) }
    }

    /// Seal packets (immutable).
    pub fn seal(k: &mut MemoryKernel, pid: &str, cid: &cid::Cid) -> Result<(), String> {
        let r = k.dispatch(SyscallRequest {
            agent_pid: pid.to_string(), operation: MemoryKernelOp::MemSeal,
            payload: SyscallPayload::MemSeal { cids: vec![cid.clone()] },
            reason: Some("seal".into()), vakya_id: None,
        });
        if r.outcome == OpOutcome::Success { Ok(()) } else { Err(format!("{:?}", r.outcome)) }
    }

    /// Grant read access.
    pub fn grant_read(k: &mut MemoryKernel, owner: &str, ns: &str, grantee: &str) -> Result<(), String> {
        let r = k.dispatch(SyscallRequest {
            agent_pid: owner.to_string(), operation: MemoryKernelOp::AccessGrant,
            payload: SyscallPayload::AccessGrant {
                target_namespace: ns.to_string(), grantee_pid: grantee.to_string(),
                read: true, write: false,
            },
            reason: Some("grant read".into()), vakya_id: None,
        });
        if r.outcome == OpOutcome::Success { Ok(()) }
        else { Err(format!("{:?}: {}", r.outcome, r.audit_entry.error.unwrap_or_default())) }
    }

    /// Revoke access.
    pub fn revoke(k: &mut MemoryKernel, owner: &str, ns: &str, grantee: &str) -> Result<(), String> {
        let r = k.dispatch(SyscallRequest {
            agent_pid: owner.to_string(), operation: MemoryKernelOp::AccessRevoke,
            payload: SyscallPayload::AccessRevoke {
                target_namespace: ns.to_string(), grantee_pid: grantee.to_string(),
            },
            reason: Some("revoke".into()), vakya_id: None,
        });
        if r.outcome == OpOutcome::Success { Ok(()) }
        else { Err(format!("{:?}: {}", r.outcome, r.audit_entry.error.unwrap_or_default())) }
    }
}

// ═══════════════════════════════════════════════════════════════
// KnowledgeCoordinator — knot graph + interference
// ═══════════════════════════════════════════════════════════════

pub struct KnowledgeCoordinator {
    knot: KnotEngine,
    window_sn: u64,
}

impl KnowledgeCoordinator {
    pub fn new() -> Self { Self { knot: KnotEngine::new(), window_sn: 0 } }

    /// Ingest all packets from a namespace into the knowledge graph.
    pub fn ingest_namespace(&mut self, k: &MemoryKernel, ns: &str) {
        let pkts: Vec<MemPacket> = k.packets_in_namespace(ns).into_iter().cloned().collect();
        if !pkts.is_empty() {
            self.knot.ingest_packets(&pkts, self.window_sn);
            self.window_sn += 1;
        }
    }

    /// Add entity manually.
    pub fn add_entity(&mut self, id: &str, etype: Option<&str>, attrs: BTreeMap<String, serde_json::Value>, tags: &[String]) {
        let now = chrono::Utc::now().timestamp_millis();
        self.knot.upsert_node(id, etype, attrs, tags, now, self.window_sn, None);
    }

    /// Add relationship.
    pub fn add_edge(&mut self, from: &str, to: &str, rel: &str, weight: f64) {
        let now = chrono::Utc::now().timestamp_millis();
        self.knot.upsert_edge(from, to, rel, weight, now, self.window_sn, None);
    }

    /// Query knowledge graph with RRF fusion.
    pub fn query(&self, q: &KnotQuery) -> Vec<FusedResult> { self.knot.query(q) }

    /// Entity count.
    pub fn entity_count(&self) -> usize { self.knot.nodes().len() }

    /// All entity IDs.
    pub fn entity_ids(&self) -> Vec<String> { self.knot.nodes().keys().cloned().collect() }

    /// Neighbors of an entity.
    pub fn neighbors(&self, id: &str) -> Vec<String> {
        self.knot.neighbors(id).into_iter().map(|s| s.to_string()).collect()
    }

    /// Extract state vector from packets (interference engine).
    pub fn extract_state_vector(packets: &[MemPacket], pid: &str, ns: &str, sn: u64) -> StateVector {
        interference::extract_state_vector(sn, pid, ns, packets, [0u8; 32])
    }

    /// Compute interference edges between two state vectors.
    pub fn compute_interference(old: &StateVector, new: &StateVector) -> InterferenceEdge {
        interference::compute_interference(old, new)
    }
}

impl Default for KnowledgeCoordinator {
    fn default() -> Self { Self::new() }
}

// ═══════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (MemoryKernel, String) {
        let mut k = MemoryKernel::new();
        let r = k.dispatch(SyscallRequest {
            agent_pid: "system".into(), operation: MemoryKernelOp::AgentRegister,
            payload: SyscallPayload::AgentRegister {
                agent_name: "bot".into(), namespace: "ns:bot".into(),
                role: Some("writer".into()), model: None, framework: None,
            },
            reason: None, vakya_id: None,
        });
        let pid = match r.value { SyscallValue::AgentPid(p) => p, _ => panic!() };
        k.dispatch(SyscallRequest {
            agent_pid: pid.clone(), operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty, reason: None, vakya_id: None,
        });
        (k, pid)
    }

    #[test]
    fn test_write_and_recall() {
        let (mut k, pid) = setup();
        let cid = MemoryCoordinator::write(
            &mut k, &pid, "hello world", "user:test", "pipe:test",
            PacketType::Input, None, vec![], vec![],
        ).unwrap();
        let text = MemoryCoordinator::recall(&mut k, &pid, &cid).unwrap();
        assert_eq!(text, "hello world");
    }

    #[test]
    fn test_session_lifecycle() {
        let (mut k, pid) = setup();
        let sid = MemoryCoordinator::create_session(&mut k, &pid, Some("conversation")).unwrap();
        assert!(!sid.is_empty());
        MemoryCoordinator::write(
            &mut k, &pid, "in session", "user:test", "pipe:test",
            PacketType::Input, Some(&sid), vec![], vec![],
        ).unwrap();
        let results = MemoryCoordinator::search_session(&k, &sid, 10);
        assert_eq!(results.len(), 1);
        assert!(MemoryCoordinator::close_session(&mut k, &pid, &sid).is_ok());
    }

    #[test]
    fn test_search_namespace() {
        let (mut k, pid) = setup();
        for i in 0..5 {
            MemoryCoordinator::write(
                &mut k, &pid, &format!("packet {}", i), "user:test", "pipe:test",
                PacketType::Input, None, vec![], vec![],
            ).unwrap();
        }
        let results = MemoryCoordinator::search_namespace(&k, "ns:bot", 10);
        assert_eq!(results.len(), 5);
    }

    #[test]
    fn test_namespace_isolation() {
        let (mut k, pid_a) = setup();
        // Register agent B
        let r = k.dispatch(SyscallRequest {
            agent_pid: "system".into(), operation: MemoryKernelOp::AgentRegister,
            payload: SyscallPayload::AgentRegister {
                agent_name: "other".into(), namespace: "ns:other".into(),
                role: Some("writer".into()), model: None, framework: None,
            },
            reason: None, vakya_id: None,
        });
        let pid_b = match r.value { SyscallValue::AgentPid(p) => p, _ => panic!() };
        k.dispatch(SyscallRequest {
            agent_pid: pid_b.clone(), operation: MemoryKernelOp::AgentStart,
            payload: SyscallPayload::Empty, reason: None, vakya_id: None,
        });

        // A writes
        let cid = MemoryCoordinator::write(
            &mut k, &pid_a, "secret", "user:a", "pipe:test",
            PacketType::Input, None, vec![], vec![],
        ).unwrap();

        // B can't read
        let result = MemoryCoordinator::recall(&mut k, &pid_b, &cid);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("DENIED"));

        // Grant and read
        MemoryCoordinator::grant_read(&mut k, &pid_a, "ns:bot", &pid_b).unwrap();
        let text = MemoryCoordinator::recall(&mut k, &pid_b, &cid).unwrap();
        assert_eq!(text, "secret");
    }

    #[test]
    fn test_seal() {
        let (mut k, pid) = setup();
        let cid = MemoryCoordinator::write(
            &mut k, &pid, "immutable", "user:test", "pipe:test",
            PacketType::Input, None, vec![], vec![],
        ).unwrap();
        assert!(MemoryCoordinator::seal(&mut k, &pid, &cid).is_ok());
        assert!(k.is_sealed(&cid));
    }

    #[test]
    fn test_knowledge_coordinator() {
        let (mut k, pid) = setup();
        MemoryCoordinator::write(
            &mut k, &pid, "patient has diabetes", "user:test", "pipe:test",
            PacketType::Input, None, vec!["patient:001".into(), "condition:diabetes".into()], vec!["medical".into()],
        ).unwrap();

        let mut kc = KnowledgeCoordinator::new();
        kc.ingest_namespace(&k, "ns:bot");
        assert!(kc.entity_count() >= 2);
        assert!(kc.entity_ids().contains(&"patient:001".to_string()));
    }
}
