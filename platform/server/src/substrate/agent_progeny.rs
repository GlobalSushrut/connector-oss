//! **Agent Progeny v1** — kernel-authoritative lifecycle tree (real parent/child PIDs).
//!
//! Fixes the classic split-brain: in-memory `agent_lifecycle::AgentRegistry` vs kernel ACBs.
//! **Source of truth = VAC kernel** `parent_pid` / `child_pids` on every agent.

use serde::{Deserialize, Serialize};
use serde_json::json;
use vac_core::kernel::{MemoryKernel, SyscallRequest, SyscallPayload, SyscallValue};
use vac_core::types::{MemoryKernelOp, OpOutcome, AgentStatus};

use crate::state::SharedState;

pub const SCHEMA: &str = "agent_progeny.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgenyCaps {
    pub max_tree_depth: u32,
    pub max_children_per_agent: u32,
}

impl Default for ProgenyCaps {
    fn default() -> Self {
        Self {
            max_tree_depth: std::env::var("CONNECTOR_AGENT_MAX_DEPTH")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(12),
            max_children_per_agent: std::env::var("CONNECTOR_AGENT_MAX_CHILDREN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(32),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgenyTreeNode {
    pub agent_pid: String,
    pub agent_name: String,
    pub namespace: String,
    pub kernel_status: String,
    pub lifecycle: String,
    pub parent_pid: Option<String>,
    pub depth: u32,
    pub children: Vec<ProgenyTreeNode>,
}

#[derive(Debug, Clone)]
pub enum ProgenyError {
    ParentNotFound(String),
    ParentTerminated(String),
    ParentNotRunnable(String),
    DepthExceeded { depth: u32, max: u32 },
    ChildrenCapExceeded { count: u32, max: u32 },
    CycleDetected,
    ChildNotFound(String),
}

impl ProgenyError {
    pub fn message(&self) -> String {
        match self {
            ProgenyError::ParentNotFound(p) => format!("parent agent '{p}' not found in kernel"),
            ProgenyError::ParentTerminated(p) => format!("parent agent '{p}' is terminated"),
            ProgenyError::ParentNotRunnable(p) => format!("parent agent '{p}' cannot spawn children"),
            ProgenyError::DepthExceeded { depth, max } => {
                format!("progeny depth {depth} exceeds max {max}")
            }
            ProgenyError::ChildrenCapExceeded { count, max } => {
                format!("parent has {count} children (max {max})")
            }
            ProgenyError::CycleDetected => "progeny link would create cycle".into(),
            ProgenyError::ChildNotFound(p) => format!("child agent '{p}' not found"),
        }
    }
}

pub fn kernel_lifecycle_label(status: &AgentStatus) -> &'static str {
    match status {
        AgentStatus::Registered => "creating",
        AgentStatus::Running => "active",
        AgentStatus::Suspended => "paused",
        AgentStatus::Waiting => "idle",
        AgentStatus::Completed => "idle",
        AgentStatus::Failed => "destroying",
        AgentStatus::Terminated => "destroyed",
    }
}

pub fn parent_can_spawn(status: &AgentStatus) -> bool {
    matches!(
        status,
        AgentStatus::Registered | AgentStatus::Running | AgentStatus::Waiting | AgentStatus::Suspended
    )
}

/// Depth of `agent_pid` walking `parent_pid` chain in kernel (0 = root).
pub fn progeny_depth(k: &MemoryKernel, agent_pid: &str) -> u32 {
    let mut depth = 0u32;
    let mut current = agent_pid.to_string();
    let mut seen = std::collections::HashSet::new();
    while let Some(acb) = k.get_agent(&current) {
        if !seen.insert(current.clone()) {
            break;
        }
        match &acb.parent_pid {
            Some(p) => {
                depth += 1;
                current = p.clone();
            }
            None => break,
        }
        if depth > 128 {
            break;
        }
    }
    depth
}

fn would_create_cycle(k: &MemoryKernel, child_pid: &str, parent_pid: &str) -> bool {
    let mut walk = parent_pid.to_string();
    let mut seen = std::collections::HashSet::new();
    while let Some(acb) = k.get_agent(&walk) {
        if walk == child_pid {
            return true;
        }
        if !seen.insert(walk.clone()) {
            return true;
        }
        match &acb.parent_pid {
            Some(p) => walk = p.clone(),
            None => return false,
        }
    }
    false
}

/// Link child to parent in kernel ACB (authoritative progeny edge).
pub fn link_progeny(
    k: &mut MemoryKernel,
    child_pid: &str,
    parent_pid: &str,
    caps: &ProgenyCaps,
) -> Result<(), ProgenyError> {
    if child_pid == parent_pid {
        return Err(ProgenyError::CycleDetected);
    }
    if would_create_cycle(k, child_pid, parent_pid) {
        return Err(ProgenyError::CycleDetected);
    }

    let parent_status = k
        .get_agent(parent_pid)
        .map(|a| a.status.clone())
        .ok_or_else(|| ProgenyError::ParentNotFound(parent_pid.to_string()))?;

    if parent_status == AgentStatus::Terminated {
        return Err(ProgenyError::ParentTerminated(parent_pid.to_string()));
    }
    if !parent_can_spawn(&parent_status) {
        return Err(ProgenyError::ParentNotRunnable(parent_pid.to_string()));
    }

    let parent_children = k
        .get_agent(parent_pid)
        .map(|a| a.child_pids.len() as u32)
        .unwrap_or(0);
    if parent_children >= caps.max_children_per_agent {
        return Err(ProgenyError::ChildrenCapExceeded {
            count: parent_children,
            max: caps.max_children_per_agent,
        });
    }

    let child_depth = progeny_depth(k, parent_pid) + 1;
    if child_depth > caps.max_tree_depth {
        return Err(ProgenyError::DepthExceeded {
            depth: child_depth,
            max: caps.max_tree_depth,
        });
    }

    if k.get_agent(child_pid).is_none() {
        return Err(ProgenyError::ChildNotFound(child_pid.to_string()));
    }

    {
        let child = k.agents_mut().get_mut(child_pid).unwrap();
        child.parent_pid = Some(parent_pid.to_string());
    }
    {
        let parent = k.agents_mut().get_mut(parent_pid).unwrap();
        if !parent.child_pids.iter().any(|c| c == child_pid) {
            parent.child_pids.push(child_pid.to_string());
        }
    }

    Ok(())
}

pub struct KernelRegisterParams<'a> {
    pub agent_name: &'a str,
    pub namespace: &'a str,
    pub role: Option<String>,
    pub model: Option<String>,
    pub framework: Option<String>,
    pub parent_kernel_pid: Option<&'a str>,
    pub reason: String,
}

/// Register + start agent in kernel; optionally link to parent progeny tree.
pub fn register_with_progeny(
    state: &SharedState,
    params: KernelRegisterParams<'_>,
    actor: &super::agent_lifecycle_gate::LifecycleActor,
) -> Result<String, ProgenyError> {
    super::agent_lifecycle_gate::register_and_start(state, params, actor)
        .map_err(|e| ProgenyError::ChildNotFound(e))
}

pub fn persist_progeny_meta(state: &SharedState, kernel_pid: &str, parent: Option<&str>) {
    let mut es = state.engine_store.lock().unwrap();
    let _ = es.folder_put(
        "agent_progeny",
        kernel_pid,
        &json!({
            "kernel_pid": kernel_pid,
            "parent_pid": parent,
            "linked_at": chrono::Utc::now().to_rfc3339(),
            "schema": SCHEMA,
        }),
    );
}

/// Collect all descendants (BFS order — children before parents for termination).
pub fn collect_descendants(k: &MemoryKernel, root: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(root.to_string());
    let mut seen = std::collections::HashSet::new();

    while let Some(pid) = queue.pop_front() {
        if !seen.insert(pid.clone()) {
            continue;
        }
        if let Some(acb) = k.get_agent(&pid) {
            for child in &acb.child_pids {
                if !seen.contains(child) {
                    queue.push_back(child.clone());
                }
            }
        }
        if pid != root {
            out.push(pid);
        }
    }
    out
}

/// Terminate agent and all kernel descendants (deepest children first).
pub fn terminate_with_progeny(
    state: &SharedState,
    kernel_pid: &str,
    reason: &str,
) -> Vec<String> {
    terminate_with_progeny_as(
        state,
        kernel_pid,
        reason,
        &super::agent_lifecycle_gate::LifecycleActor::system("progeny_terminate"),
    )
}

/// Terminate subtree with explicit lifecycle actor (operator HTTP, admin bulk, etc.).
pub fn terminate_with_progeny_as(
    state: &SharedState,
    kernel_pid: &str,
    reason: &str,
    actor: &super::agent_lifecycle_gate::LifecycleActor,
) -> Vec<String> {
    let descendants = {
        let k = state.kernel.lock().unwrap();
        collect_descendants(&k, kernel_pid)
    };

    let mut terminated = Vec::new();
    for pid in descendants.iter().rev() {
        if terminate_one_kernel(state, pid, reason, actor) {
            terminated.push(pid.clone());
        }
    }
    if terminate_one_kernel(state, kernel_pid, reason, actor) {
        terminated.push(kernel_pid.to_string());
    }
    terminated
}

fn terminate_one_kernel(
    state: &SharedState,
    kernel_pid: &str,
    reason: &str,
    actor: &super::agent_lifecycle_gate::LifecycleActor,
) -> bool {
    {
        let mut k = state.kernel.lock().unwrap();
        if k.get_agent(kernel_pid).is_none() {
            return false;
        }
        unlink_from_parent(&mut k, kernel_pid);
    }
    super::agent_lifecycle_gate::terminate_gated(state, kernel_pid, actor, reason)
}

fn unlink_from_parent(k: &mut MemoryKernel, child_pid: &str) {
    let parent = k
        .get_agent(child_pid)
        .and_then(|c| c.parent_pid.clone());
    if let Some(parent_pid) = parent {
        if let Some(parent) = k.agents_mut().get_mut(&parent_pid) {
            parent.child_pids.retain(|c| c != child_pid);
        }
    }
}

fn build_tree_node(k: &MemoryKernel, pid: &str, depth: u32) -> Option<ProgenyTreeNode> {
    let acb = k.get_agent(pid)?;
    let children: Vec<ProgenyTreeNode> = acb
        .child_pids
        .iter()
        .filter_map(|c| build_tree_node(k, c, depth + 1))
        .collect();

    Some(ProgenyTreeNode {
        agent_pid: pid.to_string(),
        agent_name: acb.agent_name.clone(),
        namespace: acb.namespace.clone(),
        kernel_status: format!("{:?}", acb.status),
        lifecycle: kernel_lifecycle_label(&acb.status).to_string(),
        parent_pid: acb.parent_pid.clone(),
        depth,
        children,
    })
}

/// Full progeny forest from kernel roots (no parent_pid).
pub fn progeny_forest(state: &SharedState) -> serde_json::Value {
    let k = state.kernel.lock().unwrap();
    let roots: Vec<String> = k
        .agents()
        .iter()
        .filter(|(_, acb)| acb.parent_pid.is_none() && acb.status != AgentStatus::Terminated)
        .map(|(pid, _)| pid.clone())
        .collect();

    let trees: Vec<ProgenyTreeNode> = roots
        .iter()
        .filter_map(|r| build_tree_node(&k, r, 0))
        .collect();

    json!({
        "ok": true,
        "schema": SCHEMA,
        "source_of_truth": "vac_kernel_acb",
        "agent_count": k.agent_count(),
        "root_count": trees.len(),
        "caps": ProgenyCaps::default(),
        "forest": trees,
    })
}

pub fn agent_progeny_detail(state: &SharedState, kernel_pid: &str) -> serde_json::Value {
    let k = state.kernel.lock().unwrap();
    match build_tree_node(&k, kernel_pid, progeny_depth(&k, kernel_pid)) {
        Some(node) => json!({ "ok": true, "schema": SCHEMA, "subtree": node }),
        None => json!({ "ok": false, "error": "agent_not_found", "agent_pid": kernel_pid }),
    }
}

pub fn lifecycle_standard_json() -> serde_json::Value {
    json!({
        "schema": SCHEMA,
        "principle": "Kernel ACB parent_pid/child_pids is the only progeny tree — not a parallel in-memory registry.",
        "kernel_status_map": {
            "registered": "creating",
            "running": "active",
            "suspended": "paused",
            "waiting": "idle",
            "completed": "idle",
            "failed": "destroying",
            "terminated": "destroyed",
        },
        "operations": {
            "register": "AgentRegister + AgentStart + optional link_progeny",
            "terminate": "terminate_with_progeny — descendants first, then parent",
            "cascade": "graph_firewall parent_quarantine_cascade reads same kernel tree",
        },
        "caps": ProgenyCaps::default(),
        "not_this": [
            "agent_lifecycle::AgentRegistry in-memory tree (orphaned — use kernel progeny)",
            "engine_store parent_pid without kernel link",
            "Philosophical lifecycle state without kernel AgentStatus backing",
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use vac_core::kernel::MemoryKernel;

    fn register_agent(k: &mut MemoryKernel, name: &str, ns: &str) -> String {
        let r = k.dispatch(SyscallRequest {
            agent_pid: "system".into(),
            operation: MemoryKernelOp::AgentRegister,
            payload: SyscallPayload::AgentRegister {
                agent_name: name.into(),
                namespace: ns.into(),
                role: None,
                model: None,
                framework: None,
            },
            reason: None,
            vakya_id: None,
            trace_parent: None,
            trace_state: None,
            api_version: None,
        });
        match r.value {
            SyscallValue::AgentPid(p) => p,
            _ => panic!("register failed"),
        }
    }

    #[test]
    fn link_progeny_sets_parent_child() {
        let mut k = MemoryKernel::new();
        let caps = ProgenyCaps {
            max_tree_depth: 5,
            max_children_per_agent: 10,
        };
        let root = register_agent(&mut k, "root", "/m/root");
        let child = register_agent(&mut k, "child", "/m/child");
        link_progeny(&mut k, &child, &root, &caps).unwrap();
        assert_eq!(k.get_agent(&child).unwrap().parent_pid.as_deref(), Some(root.as_str()));
        assert!(k.get_agent(&root).unwrap().child_pids.contains(&child));
    }

    #[test]
    fn depth_cap_enforced() {
        let mut k = MemoryKernel::new();
        let caps = ProgenyCaps {
            max_tree_depth: 2,
            max_children_per_agent: 10,
        };
        let a = register_agent(&mut k, "a", "/m/a");
        let b = register_agent(&mut k, "b", "/m/b");
        let c = register_agent(&mut k, "c", "/m/c");
        link_progeny(&mut k, &b, &a, &caps).unwrap();
        link_progeny(&mut k, &c, &b, &caps).unwrap();
        let d = register_agent(&mut k, "d", "/m/d");
        let err = link_progeny(&mut k, &d, &c, &caps);
        assert!(matches!(err, Err(ProgenyError::DepthExceeded { .. })));
    }

    #[test]
    fn collect_descendants_order() {
        let mut k = MemoryKernel::new();
        let caps = ProgenyCaps::default();
        let root = register_agent(&mut k, "root", "/m/root");
        let c1 = register_agent(&mut k, "c1", "/m/c1");
        let c2 = register_agent(&mut k, "c2", "/m/c2");
        link_progeny(&mut k, &c1, &root, &caps).unwrap();
        link_progeny(&mut k, &c2, &root, &caps).unwrap();
        let desc = collect_descendants(&k, &root);
        assert_eq!(desc.len(), 2);
        assert!(desc.contains(&c1));
        assert!(desc.contains(&c2));
    }
}
