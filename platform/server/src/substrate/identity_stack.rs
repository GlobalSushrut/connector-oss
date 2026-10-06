//! Identity stack gate — character + last memory + address relation graph.
//!
//! Augmented effects (LLM, tools, memory, MCP, pipelines) are denied unless
//! the acting agent has:
//!   1. An identity **character** (name + purpose/acume)
//!   2. A **last memory** packet (self-history)
//!   3. An **address relation identity graph** for the target address
//!      (the address is a node with ≥1 relation edge to this agent's identity)
//!
//! Missing any pillar → no automated grant. A digest-bound HITL approval
//! can authorize that one action.

use sha2::{Digest, Sha256};

use crate::error::{ConnectorError, DenialReason};
use crate::services::admission::AdmissionOp;
use crate::state::SharedState;

pub const SCHEMA: &str = "identity_stack.v1";
pub const ADDRESS_GRAPH_FOLDER: &str = "address_identity_graph";
pub const LAST_MEMORY_FOLDER: &str = "identity_last_memory";

#[derive(Debug, Clone, Default)]
pub struct IdentityStackSnapshot {
    pub has_character: bool,
    pub character_name: Option<String>,
    pub character_purpose: Option<String>,
    pub has_last_memory: bool,
    pub last_memory_at_ms: Option<i64>,
    pub last_memory_cid: Option<String>,
    pub address: String,
    pub address_type: String,
    pub has_address_identity_graph: bool,
    pub has_address_rules_contract: bool,
    pub has_address_hitl_contract: bool,
    pub relation_count: usize,
    pub missing: Vec<String>,
}

pub fn identity_stack_enforce_enabled() -> bool {
    let playground = std::env::var("CONNECTOR_PLAYGROUND")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
        .unwrap_or(false);
    if playground {
        // Hosted trial: Talk/tools use minted lanes; do not fail-closed identity stack from pilots.
        let force = std::env::var("CONNECTOR_IDENTITY_STACK_ENFORCE")
            .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"))
            .unwrap_or(false);
        return force;
    }
    let off = std::env::var("CONNECTOR_IDENTITY_STACK_ENFORCE")
        .map(|v| matches!(v.trim(), "0" | "false" | "FALSE" | "off" | "no"))
        .unwrap_or(false);
    if crate::services::runtime_control::defense_strict_enabled()
        || crate::services::intelligence_authority::lifecycle_auth_strict()
        || crate::kernel::agent_principal::intelligence_hardening_on()
    {
        return true;
    }
    !off
}

pub fn action_address(op: &AdmissionOp, namespace: &str) -> String {
    match op {
        AdmissionOp::LlmChat => format!("llm:{namespace}"),
        AdmissionOp::MemoryWrite => format!("memory:{namespace}"),
        AdmissionOp::MemoryRead { namespace } => format!("memory.read:{namespace}"),
        AdmissionOp::ToolDispatch { tool_id } => format!("tool:{tool_id}"),
        AdmissionOp::McpCall { tool_name } => format!("mcp:{tool_name}"),
        AdmissionOp::PipelineStep { pipeline_id, .. } => format!("pipeline:{pipeline_id}"),
        AdmissionOp::ConpCommand { capability_id, .. } => format!("conp:{capability_id}"),
    }
}

fn non_empty(s: Option<&str>) -> Option<String> {
    s.map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn inspect_character(state: &SharedState, api_pid: &str) -> (bool, Option<String>, Option<String>) {
    let spec = crate::kernel::intelligence_spec::load_spec_doc(state.as_ref(), api_pid);
    let spec_name = spec
        .as_ref()
        .and_then(|s| s.pointer("/metadata/name"))
        .and_then(|x| x.as_str())
        .and_then(|s| non_empty(Some(s)));
    let spec_purpose = spec
        .as_ref()
        .and_then(|s| s.pointer("/spec/purpose"))
        .and_then(|x| x.as_str())
        .and_then(|s| non_empty(Some(s)));

    let setup = crate::kernel::agent_identity_envelope::load_setup(state.as_ref(), api_pid);
    let setup_name = setup
        .as_ref()
        .and_then(|s| non_empty(Some(s.name.as_str())));
    let setup_purpose = setup.as_ref().and_then(|s| {
        let from_use_case = s.use_case_def.as_ref().and_then(|v| {
            v.as_str()
                .map(str::to_string)
                .or_else(|| v.get("purpose").and_then(|p| p.as_str()).map(str::to_string))
                .or_else(|| Some(v.to_string()))
        });
        from_use_case
            .and_then(|s| non_empty(Some(&s)))
            .or_else(|| non_empty(Some(s.acume.as_str())))
    });

    let name = spec_name.or(setup_name);
    let purpose = spec_purpose.or(setup_purpose);
    let ok = name.is_some() && purpose.is_some();
    (ok, name, purpose)
}

fn inspect_last_memory(
    state: &SharedState,
    api_pid: &str,
    namespace: &str,
) -> (bool, Option<i64>, Option<String>) {
    let kernel_pid = crate::services::agents::resolve_kernel_pid(state, api_pid).0;
    let Ok(k) = state.kernel.lock() else {
        return (false, None, None);
    };
    let ns_candidates = {
        let mut ns = vec![namespace.to_string()];
        if let Some(acb) = k.get_agent(&kernel_pid).or_else(|| k.get_agent(api_pid)) {
            ns.push(acb.namespace.clone());
        }
        ns
    };

    let mut best_ts: Option<i64> = None;
    let mut best_cid: Option<String> = None;
    for p in k.all_packets() {
        let actor = p
            .authority
            .actor
            .as_deref()
            .filter(|s| !s.is_empty())
            .unwrap_or(p.subject_id.as_str());
        let actor_ok = actor == api_pid
            || actor == kernel_pid
            || p.subject_id == api_pid
            || p.subject_id == kernel_pid
            || p.namespace
                .as_deref()
                .map(|n| ns_candidates.iter().any(|c| n == c || n.contains(api_pid)))
                .unwrap_or(false);
        if !actor_ok {
            continue;
        }
        let ts = p.index.ts;
        if best_ts.map(|b| ts >= b).unwrap_or(true) {
            best_ts = Some(ts);
            best_cid = Some(p.index.packet_cid.to_string());
        }
    }
    drop(k);
    if best_ts.is_some() {
        return (true, best_ts, best_cid);
    }
    if let Ok(es) = state.engine_store.lock() {
        if let Some(doc) = es
            .folder_get(LAST_MEMORY_FOLDER, api_pid)
            .ok()
            .flatten()
        {
            let at = doc.get("at_ms").and_then(|x| x.as_i64());
            let cid = doc
                .get("cid")
                .and_then(|x| x.as_str())
                .map(str::to_string);
            return (true, at, cid);
        }
    }
    (false, None, None)
}

/// Stable engine-store key for an address identity graph document.
pub fn graph_key(address: &str) -> String {
    address
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '.' | '-' | '_') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Legacy key used by early playground seeders (`:`/`/` → `_`).
pub fn graph_key_legacy_underscores(address: &str) -> String {
    address.replace([':', '/'], "_")
}

fn identity_keys(api_pid: &str, kernel_pid: &str) -> Vec<String> {
    let mut keys = vec![
        api_pid.to_string(),
        kernel_pid.to_string(),
        format!("agent:{api_pid}"),
        format!("m:{api_pid}"),
        format!("addr:{api_pid}"),
    ];
    if kernel_pid != api_pid {
        keys.push(format!("m:{kernel_pid}"));
        keys.push(format!("agent:{kernel_pid}"));
    }
    keys
}

fn node_matches_address(node_id: &str, address: &str) -> bool {
    let n = node_id.to_ascii_lowercase();
    let a = address.to_ascii_lowercase();
    n == a || n.contains(&a) || a.contains(&n)
}

fn inspect_address_graph(
    state: &SharedState,
    api_pid: &str,
    address: &str,
) -> (bool, usize) {
    let kernel_pid = crate::services::agents::resolve_kernel_pid(state, api_pid).0;
    let ids = identity_keys(api_pid, &kernel_pid);
    let mut relations = 0usize;
    let mut address_node = false;

    if let Ok(es) = state.engine_store.lock() {
        let key = graph_key(address);
        let legacy = graph_key_legacy_underscores(address);
        let stored = es
            .folder_get(ADDRESS_GRAPH_FOLDER, &key)
            .ok()
            .flatten()
            .or_else(|| {
                es.folder_get(ADDRESS_GRAPH_FOLDER, &legacy)
                    .ok()
                    .flatten()
            })
            .or_else(|| {
                es.folder_get(ADDRESS_GRAPH_FOLDER, &format!("{api_pid}::{key}"))
                    .ok()
                    .flatten()
            });
        if let Some(doc) = stored {
            let nodes = doc.get("nodes").and_then(|v| v.as_array());
            let edges = doc.get("edges").and_then(|v| v.as_array());
            if let Some(nodes) = nodes {
                address_node |= nodes.iter().any(|n| {
                    n.get("node_id")
                        .and_then(|x| x.as_str())
                        .map(|id| node_matches_address(id, address))
                        .unwrap_or(false)
                });
            }
            if let Some(edges) = edges {
                for e in edges {
                    let from = e.get("from_node_id").and_then(|x| x.as_str()).unwrap_or("");
                    let to = e.get("to_node_id").and_then(|x| x.as_str()).unwrap_or("");
                    let touches_addr = node_matches_address(from, address) || node_matches_address(to, address);
                    let touches_self = ids.iter().any(|id| {
                        from.eq_ignore_ascii_case(id) || to.eq_ignore_ascii_case(id) || from.contains(id) || to.contains(id)
                    });
                    if touches_addr && touches_self {
                        relations += 1;
                    }
                }
            }
        }
    }

    if let Ok(knot) = state.knot.lock() {
        let addr_nodes: Vec<String> = knot
            .nodes()
            .keys()
            .filter(|k| node_matches_address(k, address))
            .cloned()
            .collect();
        if !addr_nodes.is_empty() {
            address_node = true;
        }
        for node in &addr_nodes {
            for e in knot.edges_from(node) {
                if ids.iter().any(|id| e.to.contains(id) || id.contains(&e.to)) {
                    relations += 1;
                }
            }
            for e in knot.edges_to(node) {
                if ids.iter().any(|id| e.from.contains(id) || id.contains(&e.from)) {
                    relations += 1;
                }
            }
        }
        for id in &ids {
            if knot.get_node(id).is_some() {
                for e in knot.edges_from(id) {
                    if node_matches_address(&e.to, address) {
                        address_node = true;
                        relations += 1;
                    }
                }
            }
        }
    }

    (address_node && relations > 0, relations)
}

pub fn inspect(
    state: &SharedState,
    api_pid: &str,
    namespace: &str,
    op: &AdmissionOp,
) -> IdentityStackSnapshot {
    let raw_addr = action_address(op, namespace);
    let caged = crate::kernel::address_cage::classify_address(&raw_addr, api_pid);
    let (has_character, character_name, character_purpose) = inspect_character(state, api_pid);
    let (has_last_memory, last_memory_at_ms, last_memory_cid) =
        inspect_last_memory(state, api_pid, namespace);
    let (has_address_identity_graph, relation_count) =
        inspect_address_graph(state, api_pid, &caged.address);
    let has_address_rules_contract =
        crate::kernel::address_contracts::load_rules(state.as_ref(), &caged.address).is_some();
    let has_address_hitl_contract =
        crate::kernel::address_contracts::load_hitl(state.as_ref(), &caged.address).is_some();

    let mut missing = Vec::new();
    if !has_character {
        missing.push("identity_character".into());
    }
    if !has_last_memory {
        missing.push("last_memory".into());
    }
    if !has_address_identity_graph {
        missing.push("address_relation_identity_graph".into());
    }
    if !has_address_rules_contract {
        missing.push("address_rules_contract".into());
    }
    if !has_address_hitl_contract {
        missing.push("address_hitl_contract".into());
    }

    IdentityStackSnapshot {
        has_character,
        character_name,
        character_purpose,
        has_last_memory,
        last_memory_at_ms,
        last_memory_cid,
        address: caged.address,
        address_type: caged.address_type,
        has_address_identity_graph,
        has_address_rules_contract,
        has_address_hitl_contract,
        relation_count,
        missing,
    }
}

fn stack_digest(api_pid: &str, op: &AdmissionOp, snap: &IdentityStackSnapshot) -> String {
    let raw = format!(
        "identity_stack|{}|{}|{}|{}",
        api_pid,
        op.slug(),
        snap.address,
        snap.missing.join(",")
    );
    hex::encode(Sha256::digest(raw.as_bytes()))
}

/// Fail-closed: missing character / last memory / address graph → HITL or deny.
pub fn enforce(
    state: &SharedState,
    api_pid: &str,
    namespace: &str,
    op: &AdmissionOp,
) -> Result<IdentityStackSnapshot, ConnectorError> {
    // The model's own lane is not a world address. Mint memory, the
    // relation, and RULES + HITL for `llm:{namespace}` only. Tools stay
    // incomplete until the operator mints those addresses.
    if matches!(op, AdmissionOp::LlmChat) {
        crate::services::agents::ensure_self_talk_lane(state, api_pid, namespace);
    }
    if crate::services::playground::is_playground_mode() {
        crate::services::agents::ensure_playground_talk_lane(state, api_pid);
    }
    let snap = inspect(state, api_pid, namespace, op);
    if snap.missing.is_empty() {
        return Ok(snap);
    }
    if !identity_stack_enforce_enabled()
        && !crate::substrate::probabilistic_llm::distrust_enforced()
    {
        return Ok(snap);
    }
    // Playground + distrust: after lane mint, still incomplete → allow Talk as
    // live_measure (HITL Force remains available). Production non-playground stays fail-closed.
    if crate::services::playground::is_playground_mode()
        && matches!(op, AdmissionOp::LlmChat)
        && !identity_stack_enforce_enabled()
    {
        return Ok(snap);
    }

    let digest = stack_digest(api_pid, op, &snap);
    if crate::services::agents::hitl_consume_for_action(
        Some(state),
        api_pid,
        &digest,
        None,
        None,
    )
    .is_ok()
    {
        return Ok(snap);
    }

    let description = format!(
        "Identity stack incomplete for {} on {}: missing {}. Character, last memory, address relation graph, and the address RULES + HITL contracts (separate) are required before any augmented action.",
        op.slug(),
        snap.address,
        snap.missing.join(", ")
    );
    let request_id = crate::services::agents::hitl_submit_bound(
        api_pid,
        "identity_stack.augmented_action",
        &description,
        &digest,
        Some(serde_json::json!({
            "schema": SCHEMA,
            "missing": snap.missing,
            "address": snap.address,
            "address_type": snap.address_type,
            "operation": op.slug(),
            "has_character": snap.has_character,
            "has_last_memory": snap.has_last_memory,
            "has_address_identity_graph": snap.has_address_identity_graph,
            "has_address_rules_contract": snap.has_address_rules_contract,
            "has_address_hitl_contract": snap.has_address_hitl_contract,
        })),
        Some(SCHEMA.into()),
        None,
        Some(state),
    );

    Err(ConnectorError::new(
        DenialReason::CapabilityRequired,
        format!(
            "Augmented action denied: identity stack incomplete ({}). Human approval required.",
            snap.missing.join(", ")
        ),
    )
    .with_denied_resource(snap.address.clone())
    .with_hint(format!(
        "hitl_required request_id={request_id} — approve POST /api/v1/agents/{api_pid}/hitl/{request_id}/approve after establishing character, last memory, and the address relation identity graph for {}",
        snap.address
    ))
    .with_example_fix(format!(
        "curl -X POST /api/v1/agents/{api_pid}/hitl/{request_id}/approve\n# or persist character (IntelligenceSpec name+purpose), write a memory packet, and store {ADDRESS_GRAPH_FOLDER} for {}",
        snap.address
    )))
}

pub fn posture_json() -> serde_json::Value {
    serde_json::json!({
        "schema": SCHEMA,
        "enforce": identity_stack_enforce_enabled(),
        "honesty": "Without identity character, last memory, address relation graph, and the address's separate RULES + HITL contracts, no augmented action is allowed unless a human approves that exact digest.",
        "pillars": [
            "identity_character",
            "last_memory",
            "address_relation_identity_graph",
            "address_rules_contract",
            "address_hitl_contract"
        ],
        "hitl": "digest-bound identity_stack.augmented_action",
        "graph_folder": ADDRESS_GRAPH_FOLDER,
        "opt_out": "CONNECTOR_IDENTITY_STACK_ENFORCE=0 (ignored under defense/lifecycle/hardening)",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_address_is_stable() {
        assert_eq!(
            action_address(&AdmissionOp::LlmChat, "gateway/a1"),
            "llm:gateway/a1"
        );
        assert_eq!(
            action_address(
                &AdmissionOp::ToolDispatch {
                    tool_id: "mcp:search".into()
                },
                "tools/mcp"
            ),
            "tool:mcp:search"
        );
    }

    #[test]
    fn graph_key_sanitizes() {
        assert_eq!(graph_key("tool:mcp/search"), "tool:mcp/search");
        assert_eq!(graph_key("llm:gateway/a 1"), "llm:gateway/a_1");
    }
}
