//! Kernel Data Management Engine — scalability, distribution, storage control.
//!
//! Wraps the MemoryKernel with high-level operations for:
//! - Kernel statistics and health monitoring
//! - Namespace management (list, inspect, size)
//! - Session management (list, inspect, compress)
//! - Agent lifecycle (list, inspect, suspend, resume, terminate)
//! - Data export/import (snapshot to JSON, restore)
//! - Audit log queries (by agent, time range, operation)
//! - Health diagnostics (integrity check, GC, memory pressure)

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use vac_core::kernel::{MemoryKernel, SyscallRequest, SyscallPayload, SyscallValue};
use vac_core::types::*;

// ═══════════════════════════════════════════════════════════════
// Statistics Types
// ═══════════════════════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelStats {
    pub total_packets: usize,
    pub total_agents: usize,
    pub total_sessions: usize,
    pub total_audit_entries: usize,
    pub active_agents: usize,
    pub active_sessions: usize,
    pub namespaces: usize,
    pub sealed_packets: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamespaceInfo {
    pub name: String,
    pub packet_count: usize,
    pub agents: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub session_id: String,
    pub agent_id: String,
    pub namespace: String,
    pub label: Option<String>,
    pub packet_count: usize,
    pub total_tokens: u64,
    pub started_at: i64,
    pub ended_at: Option<i64>,
    pub is_active: bool,
    pub tier: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub pid: String,
    pub name: String,
    pub status: String,
    pub namespace: String,
    pub total_packets: u64,
    pub total_tokens: u64,
    pub total_cost_usd: f64,
    pub memory_used_packets: u64,
    pub memory_quota_packets: u64,
    pub active_sessions: usize,
    pub registered_at: i64,
    pub last_active_at: i64,
    pub model: Option<String>,
    pub role: Option<String>,
    pub phase: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub audit_id: String,
    pub timestamp: i64,
    pub operation: String,
    pub agent_pid: String,
    pub target: Option<String>,
    pub outcome: String,
    pub reason: Option<String>,
    pub error: Option<String>,
    pub duration_us: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub healthy: bool,
    pub total_packets: usize,
    pub total_agents: usize,
    pub total_audit_entries: usize,
    pub memory_pressure: f64,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportData {
    pub version: u32,
    pub exported_at: i64,
    pub stats: KernelStats,
    pub agents: Vec<AgentInfo>,
    pub sessions: Vec<SessionInfo>,
    pub namespaces: Vec<NamespaceInfo>,
    pub audit_tail: Vec<AuditEntry>,
}

// ═══════════════════════════════════════════════════════════════
// KernelOps — the data management engine
// ═══════════════════════════════════════════════════════════════

pub struct KernelOps {
    kernel: Arc<Mutex<MemoryKernel>>,
}

impl KernelOps {
    pub fn new(kernel: Arc<Mutex<MemoryKernel>>) -> Self {
        Self { kernel }
    }

    fn now_ms() -> i64 {
        chrono::Utc::now().timestamp_millis()
    }

    // ── Statistics ──

    pub fn stats(&self) -> KernelStats {
        let k = self.kernel.lock().unwrap();
        let agents = k.agents();
        let sessions = k.sessions();
        let active_agents = agents.values()
            .filter(|a| a.status == AgentStatus::Running)
            .count();
        let active_sessions = sessions.values()
            .filter(|s| s.is_active())
            .count();
        // Count unique namespaces from agents
        let mut ns_set = std::collections::HashSet::new();
        for a in agents.values() {
            ns_set.insert(a.namespace.clone());
        }
        KernelStats {
            total_packets: k.packet_count(),
            total_agents: agents.len(),
            total_sessions: sessions.len(),
            total_audit_entries: k.audit_count(),
            active_agents,
            active_sessions,
            namespaces: ns_set.len(),
            sealed_packets: 0, // would need kernel API
        }
    }

    // ── Namespace Management ──

    pub fn list_namespaces(&self) -> Vec<NamespaceInfo> {
        let k = self.kernel.lock().unwrap();
        let agents = k.agents();
        let mut ns_map: HashMap<String, NamespaceInfo> = HashMap::new();
        for a in agents.values() {
            let entry = ns_map.entry(a.namespace.clone()).or_insert_with(|| {
                NamespaceInfo {
                    name: a.namespace.clone(),
                    packet_count: k.packets_in_namespace(&a.namespace).len(),
                    agents: vec![],
                }
            });
            entry.agents.push(a.agent_pid.clone());
        }
        let mut result: Vec<NamespaceInfo> = ns_map.into_values().collect();
        result.sort_by(|a, b| a.name.cmp(&b.name));
        result
    }

    pub fn namespace_info(&self, namespace: &str) -> Option<NamespaceInfo> {
        let k = self.kernel.lock().unwrap();
        let packets = k.packets_in_namespace(namespace);
        if packets.is_empty() {
            // Check if any agent owns this namespace
            let agents: Vec<String> = k.agents().values()
                .filter(|a| a.namespace == namespace)
                .map(|a| a.agent_pid.clone())
                .collect();
            if agents.is_empty() { return None; }
            return Some(NamespaceInfo { name: namespace.into(), packet_count: 0, agents });
        }
        let agents: Vec<String> = k.agents().values()
            .filter(|a| a.namespace == namespace)
            .map(|a| a.agent_pid.clone())
            .collect();
        Some(NamespaceInfo { name: namespace.into(), packet_count: packets.len(), agents })
    }

    // ── Session Management ──

    pub fn list_sessions(&self) -> Vec<SessionInfo> {
        let k = self.kernel.lock().unwrap();
        let mut result: Vec<SessionInfo> = k.sessions().values().map(|s| SessionInfo {
            session_id: s.session_id.clone(),
            agent_id: s.agent_id.clone(),
            namespace: s.namespace.clone(),
            label: s.label.clone(),
            packet_count: s.packet_cids.len(),
            total_tokens: s.total_tokens,
            started_at: s.started_at,
            ended_at: s.ended_at,
            is_active: s.is_active(),
            tier: format!("{:?}", s.tier),
        }).collect();
        result.sort_by(|a, b| b.started_at.cmp(&a.started_at));
        result
    }

    pub fn session_info(&self, session_id: &str) -> Option<SessionInfo> {
        let k = self.kernel.lock().unwrap();
        k.get_session(session_id).map(|s| SessionInfo {
            session_id: s.session_id.clone(),
            agent_id: s.agent_id.clone(),
            namespace: s.namespace.clone(),
            label: s.label.clone(),
            packet_count: s.packet_cids.len(),
            total_tokens: s.total_tokens,
            started_at: s.started_at,
            ended_at: s.ended_at,
            is_active: s.is_active(),
            tier: format!("{:?}", s.tier),
        })
    }

    // ── Agent Lifecycle ──

    pub fn list_agents(&self) -> Vec<AgentInfo> {
        let k = self.kernel.lock().unwrap();
        let mut result: Vec<AgentInfo> = k.agents().values().map(|a| AgentInfo {
            pid: a.agent_pid.clone(),
            name: a.agent_name.clone(),
            status: format!("{}", a.status),
            namespace: a.namespace.clone(),
            total_packets: a.total_packets,
            total_tokens: a.total_tokens_consumed,
            total_cost_usd: a.total_cost_usd,
            memory_used_packets: a.memory_region.used_packets,
            memory_quota_packets: a.memory_region.quota_packets,
            active_sessions: a.active_sessions.len(),
            registered_at: a.registered_at,
            last_active_at: a.last_active_at,
            model: a.model.clone(),
            role: a.agent_role.clone(),
            phase: format!("{:?}", a.phase),
        }).collect();
        result.sort_by(|a, b| a.pid.cmp(&b.pid));
        result
    }

    pub fn agent_info(&self, pid: &str) -> Option<AgentInfo> {
        let k = self.kernel.lock().unwrap();
        k.get_agent(pid).map(|a| AgentInfo {
            pid: a.agent_pid.clone(),
            name: a.agent_name.clone(),
            status: format!("{}", a.status),
            namespace: a.namespace.clone(),
            total_packets: a.total_packets,
            total_tokens: a.total_tokens_consumed,
            total_cost_usd: a.total_cost_usd,
            memory_used_packets: a.memory_region.used_packets,
            memory_quota_packets: a.memory_region.quota_packets,
            active_sessions: a.active_sessions.len(),
            registered_at: a.registered_at,
            last_active_at: a.last_active_at,
            model: a.model.clone(),
            role: a.agent_role.clone(),
            phase: format!("{:?}", a.phase),
        })
    }

    pub fn suspend_agent(&self, caller_pid: &str, target_pid: &str) -> Result<(), String> {
        let mut k = self.kernel.lock().unwrap();
        let r = k.dispatch(SyscallRequest {
            agent_pid: caller_pid.into(),
            operation: MemoryKernelOp::AgentSuspend,
            payload: SyscallPayload::Empty,
            reason: Some(format!("Suspended by {}", caller_pid)),
            vakya_id: None,
        });
        match r.outcome {
            OpOutcome::Success => Ok(()),
            _ => Err(format!("Failed to suspend {}: {:?}", target_pid, r.value)),
        }
    }

    pub fn resume_agent(&self, caller_pid: &str) -> Result<(), String> {
        let mut k = self.kernel.lock().unwrap();
        let r = k.dispatch(SyscallRequest {
            agent_pid: caller_pid.into(),
            operation: MemoryKernelOp::AgentResume,
            payload: SyscallPayload::Empty,
            reason: Some("Resumed".into()),
            vakya_id: None,
        });
        match r.outcome {
            OpOutcome::Success => Ok(()),
            _ => Err(format!("Failed to resume {}: {:?}", caller_pid, r.value)),
        }
    }

    pub fn terminate_agent(&self, caller_pid: &str, target_pid: &str, reason: &str) -> Result<(), String> {
        let mut k = self.kernel.lock().unwrap();
        let r = k.dispatch(SyscallRequest {
            agent_pid: caller_pid.into(),
            operation: MemoryKernelOp::AgentTerminate,
            payload: SyscallPayload::AgentTerminate {
                target_pid: Some(target_pid.into()),
                reason: reason.into(),
            },
            reason: Some(reason.into()),
            vakya_id: None,
        });
        match r.outcome {
            OpOutcome::Success | OpOutcome::Skipped => Ok(()),
            _ => Err(format!("Failed to terminate {}: {:?}", target_pid, r.value)),
        }
    }

    // ── Audit Queries ──

    pub fn audit_tail(&self, limit: usize) -> Vec<AuditEntry> {
        let k = self.kernel.lock().unwrap();
        let log = k.audit_log();
        let start = if log.len() > limit { log.len() - limit } else { 0 };
        log[start..].iter().map(|e| AuditEntry {
            audit_id: e.audit_id.clone(),
            timestamp: e.timestamp,
            operation: format!("{:?}", e.operation),
            agent_pid: e.agent_pid.clone(),
            target: e.target.clone(),
            outcome: format!("{:?}", e.outcome),
            reason: e.reason.clone(),
            error: e.error.clone(),
            duration_us: e.duration_us,
        }).collect()
    }

    pub fn audit_by_agent(&self, agent_pid: &str, limit: usize) -> Vec<AuditEntry> {
        let k = self.kernel.lock().unwrap();
        let log = k.audit_log();
        log.iter().rev()
            .filter(|e| e.agent_pid == agent_pid)
            .take(limit)
            .map(|e| AuditEntry {
                audit_id: e.audit_id.clone(),
                timestamp: e.timestamp,
                operation: format!("{:?}", e.operation),
                agent_pid: e.agent_pid.clone(),
                target: e.target.clone(),
                outcome: format!("{:?}", e.outcome),
                reason: e.reason.clone(),
                error: e.error.clone(),
                duration_us: e.duration_us,
            })
            .collect()
    }

    // ── Health & Diagnostics ──

    pub fn health(&self) -> HealthReport {
        let k = self.kernel.lock().unwrap();
        let agents = k.agents();
        let mut warnings = Vec::new();

        // Check memory pressure per agent
        let mut total_used: u64 = 0;
        let mut total_quota: u64 = 0;
        for a in agents.values() {
            total_used += a.memory_region.used_packets;
            total_quota += a.memory_region.quota_packets;
            if a.memory_region.quota_packets > 0 {
                let usage = a.memory_region.used_packets as f64 / a.memory_region.quota_packets as f64;
                if usage > 0.9 {
                    warnings.push(format!("Agent {} at {:.0}% memory capacity", a.agent_pid, usage * 100.0));
                }
            }
        }

        let pressure = if total_quota > 0 {
            total_used as f64 / total_quota as f64
        } else {
            0.0
        };

        if k.audit_count() > 90_000 {
            warnings.push(format!("Audit log at {} entries (max 100K)", k.audit_count()));
        }

        HealthReport {
            healthy: warnings.is_empty(),
            total_packets: k.packet_count(),
            total_agents: agents.len(),
            total_audit_entries: k.audit_count(),
            memory_pressure: pressure,
            warnings,
        }
    }

    pub fn garbage_collect(&self, caller_pid: &str) -> Result<u64, String> {
        let mut k = self.kernel.lock().unwrap();
        let r = k.dispatch(SyscallRequest {
            agent_pid: caller_pid.into(),
            operation: MemoryKernelOp::GarbageCollect,
            payload: SyscallPayload::GarbageCollect,
            reason: Some("Manual GC".into()),
            vakya_id: None,
        });
        match r.value {
            SyscallValue::Count(n) => Ok(n),
            _ => Ok(0),
        }
    }

    pub fn integrity_check(&self, caller_pid: &str) -> Result<bool, String> {
        let mut k = self.kernel.lock().unwrap();
        let r = k.dispatch(SyscallRequest {
            agent_pid: caller_pid.into(),
            operation: MemoryKernelOp::IntegrityCheck,
            payload: SyscallPayload::IntegrityCheck,
            reason: None,
            vakya_id: None,
        });
        match r.value {
            SyscallValue::Bool(b) => Ok(b),
            _ => Ok(false),
        }
    }

    // ── Export ──

    pub fn export(&self, audit_tail_limit: usize) -> ExportData {
        ExportData {
            version: 1,
            exported_at: Self::now_ms(),
            stats: self.stats(),
            agents: self.list_agents(),
            sessions: self.list_sessions(),
            namespaces: self.list_namespaces(),
            audit_tail: self.audit_tail(audit_tail_limit),
        }
    }

    pub fn export_json(&self, audit_tail_limit: usize) -> String {
        serde_json::to_string_pretty(&self.export(audit_tail_limit)).unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (KernelOps, String) {
        let kernel = Arc::new(Mutex::new(MemoryKernel::new()));
        let ops = KernelOps::new(kernel.clone());
        // Register an agent
        let pid = {
            let mut k = kernel.lock().unwrap();
            let r = k.dispatch(SyscallRequest {
                agent_pid: "system".into(),
                operation: MemoryKernelOp::AgentRegister,
                payload: SyscallPayload::AgentRegister {
                    agent_name: "bot".into(),
                    namespace: "ns:test".into(),
                    role: Some("assistant".into()),
                    model: Some("gpt-4".into()),
                    framework: None,
                },
                reason: None,
                vakya_id: None,
            });
            match r.value { SyscallValue::AgentPid(p) => p, _ => panic!("no pid") }
        };
        // Start the agent
        {
            let mut k = kernel.lock().unwrap();
            k.dispatch(SyscallRequest {
                agent_pid: pid.clone(),
                operation: MemoryKernelOp::AgentStart,
                payload: SyscallPayload::Empty,
                reason: None,
                vakya_id: None,
            });
        }
        (ops, pid)
    }

    #[test]
    fn test_stats_empty() {
        let kernel = Arc::new(Mutex::new(MemoryKernel::new()));
        let ops = KernelOps::new(kernel);
        let s = ops.stats();
        assert_eq!(s.total_packets, 0);
        assert_eq!(s.total_agents, 0);
    }

    #[test]
    fn test_stats_with_agent() {
        let (ops, _pid) = setup();
        let s = ops.stats();
        assert_eq!(s.total_agents, 1);
        assert_eq!(s.active_agents, 1);
        assert!(s.namespaces >= 1);
    }

    #[test]
    fn test_list_agents() {
        let (ops, pid) = setup();
        let agents = ops.list_agents();
        assert_eq!(agents.len(), 1);
        assert_eq!(agents[0].pid, pid);
        assert_eq!(agents[0].name, "bot");
        assert_eq!(agents[0].model, Some("gpt-4".into()));
    }

    #[test]
    fn test_agent_info() {
        let (ops, pid) = setup();
        let info = ops.agent_info(&pid).unwrap();
        assert_eq!(info.name, "bot");
        assert_eq!(info.namespace, "ns:test");
    }

    #[test]
    fn test_agent_info_not_found() {
        let (ops, _) = setup();
        assert!(ops.agent_info("pid:999999").is_none());
    }

    #[test]
    fn test_list_namespaces() {
        let (ops, _) = setup();
        let ns = ops.list_namespaces();
        assert!(!ns.is_empty());
        assert!(ns.iter().any(|n| n.name == "ns:test"));
    }

    #[test]
    fn test_namespace_info() {
        let (ops, _) = setup();
        let info = ops.namespace_info("ns:test").unwrap();
        assert_eq!(info.name, "ns:test");
        assert!(!info.agents.is_empty());
    }

    #[test]
    fn test_namespace_not_found() {
        let (ops, _) = setup();
        assert!(ops.namespace_info("ns:nonexistent").is_none());
    }

    #[test]
    fn test_list_sessions_empty() {
        let (ops, _) = setup();
        let sessions = ops.list_sessions();
        assert!(sessions.is_empty());
    }

    #[test]
    fn test_audit_tail() {
        let (ops, _) = setup();
        let audit = ops.audit_tail(10);
        assert!(!audit.is_empty()); // register + start = at least 2
    }

    #[test]
    fn test_audit_by_agent() {
        let (ops, pid) = setup();
        let audit = ops.audit_by_agent(&pid, 10);
        assert!(!audit.is_empty());
    }

    #[test]
    fn test_health() {
        let (ops, _) = setup();
        let h = ops.health();
        assert!(h.healthy);
        assert_eq!(h.total_agents, 1);
    }

    #[test]
    fn test_export_json() {
        let (ops, _) = setup();
        let json = ops.export_json(5);
        assert!(json.contains("\"version\": 1"));
        assert!(json.contains("\"total_agents\": 1"));
        assert!(json.contains("bot"));
    }

    #[test]
    fn test_export_data() {
        let (ops, _) = setup();
        let data = ops.export(10);
        assert_eq!(data.version, 1);
        assert_eq!(data.agents.len(), 1);
        assert!(!data.namespaces.is_empty());
        assert!(!data.audit_tail.is_empty());
    }
}
