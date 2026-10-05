//! `GET /api/v1/kernel/agent-explain` — one live answer to "what is this agent
//! doing, and if it is not running, who stopped it and why".
//!
//! The operator UI opens this the moment an agent is touched. It folds every
//! gate that can hold an agent into a single ordered story:
//!
//! 1. **Lifecycle** — quarantine / pause / freeze (`intelligence_authority`)
//! 2. **Identity stack** — character, last memory, address graph, both address
//!    contracts (`substrate::identity_stack`)
//! 3. **Address DAC** — RULES verdict, then HITL verdict, then Block seals
//!    (`kernel::address_contracts`)
//! 4. **Recent denials** — what the kernel audit log actually recorded
//!
//! Plus the agent's identity (who it is) and knowledge (what it remembers), so
//! an operator can judge a block without leaving the popup.
//!
//! Read-only. Uses `address_contracts::preview`, never `evaluate`, so opening
//! the popup cannot create a kernel-final Block seal.

use axum::extract::{Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};

use crate::kernel::address_contracts as dac;
use crate::operator::honesty::operator_envelope;
use crate::services::workflow_runtime::require_admin_or_dev;
use crate::state::SharedState;

#[derive(Debug, Deserialize)]
pub struct ExplainQuery {
    pub agent_pid: String,
    #[serde(default)]
    pub namespace: Option<String>,
    /// `llm.chat` | `memory.write` | `tool:<id>` | `mcp:<name>`
    #[serde(default)]
    pub op: Option<String>,
    /// Extra tool ids to dry-run against the agent's address.
    #[serde(default)]
    pub tools: Option<String>,
}

fn parse_op(raw: Option<&str>) -> crate::services::admission::AdmissionOp {
    use crate::services::admission::AdmissionOp;
    match raw.unwrap_or("llm.chat") {
        "memory.write" => AdmissionOp::MemoryWrite,
        "conp.command" => AdmissionOp::ConpCommand {
            capability_id: "conp.command".into(),
            entity_id: String::new(),
        },
        s if s.starts_with("tool:") => AdmissionOp::ToolDispatch {
            tool_id: s.trim_start_matches("tool:").to_string(),
        },
        s if s.starts_with("mcp:") => AdmissionOp::McpCall {
            tool_name: s.trim_start_matches("mcp:").to_string(),
        },
        s if s.starts_with("conp:") => {
            let rest = s.trim_start_matches("conp:");
            let (cap, ent) = rest
                .split_once(':')
                .map(|(a, b)| (a.to_string(), b.to_string()))
                .unwrap_or_else(|| (rest.to_string(), String::new()));
            AdmissionOp::ConpCommand {
                capability_id: cap,
                entity_id: ent,
            }
        }
        _ => AdmissionOp::LlmChat,
    }
}

/// Kernel-side runtime facts. Lock is taken briefly and dropped.
fn runtime_facts(state: &SharedState, agent_pid: &str) -> (Value, Vec<Value>) {
    let kernel_pid = crate::services::agents::resolve_kernel_pid_pub(state, agent_pid).0;
    let Ok(k) = state.kernel.lock() else {
        return (json!({"known": false, "reason": "kernel lock unavailable"}), Vec::new());
    };

    let acb = k.get_agent(&kernel_pid).or_else(|| k.get_agent(agent_pid));
    let live = match acb {
        Some(a) => json!({
            "known": true,
            "kernel_pid": kernel_pid,
            "name": a.agent_name,
            "role": a.agent_role,
            "status": format!("{:?}", a.status),
            "priority": a.priority,
            "namespace": a.namespace,
            "active_sessions": a.active_sessions.len(),
            "total_packets": a.total_packets,
            "total_tokens_consumed": a.total_tokens_consumed,
            "total_cost_usd": a.total_cost_usd,
        }),
        None => json!({
            "known": false,
            "kernel_pid": kernel_pid,
            "reason": "no agent control block in kernel — never started, or reaped",
        }),
    };

    // Most recent denials attributed to this agent.
    let mut denials: Vec<Value> = k
        .audit_log()
        .iter()
        .filter(|e| e.outcome == vac_core::types::OpOutcome::Denied)
        .filter(|e| e.agent_pid == agent_pid || e.agent_pid == kernel_pid)
        .map(|e| {
            json!({
                "timestamp": e.timestamp,
                "operation": format!("{:?}", e.operation),
                "reason": e.reason,
                "error": e.error,
            })
        })
        .collect();
    denials.reverse();
    denials.truncate(8);
    (live, denials)
}

/// Name the enforcement layer from a denial string so the operator sees the
/// mechanism, not just the message.
fn classify_layer(reason: &str, error: &str) -> &'static str {
    let blob = format!("{reason} {error}").to_ascii_lowercase();
    if blob.contains("kernel block") || blob.contains("block_seal") || blob.contains("address_block")
    {
        "kernel::address_contracts (Block seal — kernel-final)"
    } else if blob.contains("address_hitl") {
        "kernel::address_contracts (address HITL contract)"
    } else if blob.contains("address_rules") || blob.contains("address access control") {
        "kernel::address_contracts (address RULES contract)"
    } else if blob.contains("identity stack") || blob.contains("identity_stack") {
        "substrate::identity_stack"
    } else if blob.contains("quarantine") || blob.contains("lifecycle") {
        "services::intelligence_authority (lifecycle gate)"
    } else if blob.contains("sgke") {
        "substrate::sgke_gate"
    } else if blob.contains("capability") || blob.contains("grant") {
        "services::admission (capability grant)"
    } else if blob.is_empty() {
        "unattributed"
    } else {
        "services::admission"
    }
}

pub async fn get_agent_explain(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<ExplainQuery>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return Json(e);
    }

    let namespace = q.namespace.clone().unwrap_or_else(|| "default".into());
    let op = parse_op(q.op.as_deref());
    let (live, denials) = runtime_facts(&state, &q.agent_pid);
    let control = crate::services::intelligence_authority::load_agent_control(&state, &q.agent_pid);
    let snap = crate::substrate::identity_stack::inspect(&state, &q.agent_pid, &namespace, &op);

    // Address DAC dry-run for the agent's target address.
    let mut tools: Vec<String> = q
        .tools
        .as_deref()
        .map(|s| {
            s.split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect()
        })
        .unwrap_or_default();
    if tools.is_empty() {
        tools.push(dac::tool_from_op(&op));
    }
    let dac_rows: Vec<Value> = tools
        .iter()
        .map(|t| dac::preview(state.as_ref(), &snap.address, t))
        .collect();
    let seals = dac::list_block_seals(state.as_ref(), Some(&snap.address));

    // Pending human approvals waiting on this agent.
    crate::services::agents::hitl_ensure_hydrated(&state);
    let pending_hitl: Vec<Value> = crate::services::agents::hitl_store_snapshot()
        .values()
        .filter(|r| r.agent_pid == q.agent_pid && r.status == "pending")
        .map(|r| {
            json!({
                "request_id": r.request_id,
                "action": r.action,
                "description": r.description,
                "created_at": r.created_at,
                "digest_bound": r.action_digest.is_some(),
            })
        })
        .collect();

    // ── Fold everything into one verdict + ordered "why" chain ──────────
    let mut why: Vec<Value> = Vec::new();
    let blocked_by_dac = dac_rows
        .iter()
        .any(|r| r.get("verdict").and_then(|v| v.as_str()) == Some("block"));
    let asks_from_dac = dac_rows
        .iter()
        .any(|r| r.get("verdict").and_then(|v| v.as_str()) == Some("ask"));

    if control.quarantined {
        why.push(json!({
            "layer": "services::intelligence_authority (lifecycle gate)",
            "severity": "block",
            "title": "Agent is quarantined",
            "detail": control.quarantine_reason.clone()
                .unwrap_or_else(|| "No reason recorded on the quarantine.".into()),
            "fix": "Unquarantine requires a linked HITL approval, or an admin force with a reason.",
            "hitl_id": control.quarantine_hitl_id.clone(),
        }));
    }
    if control.paused {
        why.push(json!({
            "layer": "services::intelligence_authority (lifecycle gate)",
            "severity": "block",
            "title": "Agent is paused",
            "detail": "Lifecycle state is paused; the kernel will not schedule it.",
            "fix": "Resume from the agent controls.",
        }));
    }
    if control.egress_isolated {
        why.push(json!({
            "layer": "kernel::address_cage",
            "severity": "warn",
            "title": "Egress isolated",
            "detail": "Outbound network is cut for this agent.",
        }));
    }
    if !snap.missing.is_empty() {
        why.push(json!({
            "layer": "substrate::identity_stack",
            "severity": "block",
            "title": format!("Identity stack incomplete ({} missing)", snap.missing.len()),
            "detail": format!("Missing: {}", snap.missing.join(", ")),
            "fix": "Every pillar must exist before any augmented action. Mint the missing ones.",
        }));
    }
    if !seals.is_empty() {
        why.push(json!({
            "layer": "kernel::address_contracts (Block seal — kernel-final)",
            "severity": "block",
            "title": format!("{} Block seal(s) on this address", seals.len()),
            "detail": "A sealed Block survives tool-name aliases, HITL approval, and model substitution.",
            "fix": "Operator unseal with the kernel root passcode, then change the RULES contract.",
        }));
    }
    if blocked_by_dac {
        why.push(json!({
            "layer": "kernel::address_contracts",
            "severity": "block",
            "title": "Address DAC denies this tool",
            "detail": "RULES blocked the capability, or the HITL contract set block for it.",
            "fix": "Edit the address RULES contract in Access Control.",
        }));
    } else if asks_from_dac {
        why.push(json!({
            "layer": "kernel::address_contracts (address HITL contract)",
            "severity": "ask",
            "title": "Human approval required",
            "detail": "RULES allow this tool; the address HITL contract gates it on a human.",
            "fix": "Approve the pending HITL request, or set the tool policy to none.",
        }));
    }
    for d in denials.iter().take(3) {
        let reason = d.get("reason").and_then(|x| x.as_str()).unwrap_or("");
        let error = d.get("error").and_then(|x| x.as_str()).unwrap_or("");
        why.push(json!({
            "layer": classify_layer(reason, error),
            "severity": "denial",
            "title": "Recent kernel denial",
            "detail": if reason.is_empty() { error } else { reason },
            "timestamp": d.get("timestamp").cloned(),
        }));
    }

    let status_str = live
        .get("status")
        .and_then(|x| x.as_str())
        .unwrap_or("Unknown")
        .to_string();
    let (verdict, headline) = if control.quarantined {
        ("quarantined", "Quarantined — the lifecycle gate is holding this agent.")
    } else if control.paused {
        ("paused", "Paused — the kernel will not schedule it.")
    } else if blocked_by_dac || !seals.is_empty() {
        ("blocked", "Blocked — the address contracts deny this action.")
    } else if !snap.missing.is_empty() {
        ("incomplete", "Denied — the identity stack is missing a required pillar.")
    } else if asks_from_dac || !pending_hitl.is_empty() {
        ("needs_human", "Waiting on a human — approval required before this proceeds.")
    } else if live.get("known").and_then(|x| x.as_bool()) == Some(true) {
        ("active", "Running — every gate is currently clear.")
    } else {
        ("unknown", "No kernel control block — the agent is not running.")
    };

    Json(operator_envelope(json!({
        "schema": "agent_explain.v1",
        "agent_pid": q.agent_pid,
        "namespace": namespace,
        "op": op.slug(),
        "verdict": verdict,
        "headline": headline,
        "kernel_status": status_str,
        "why": why,
        "live": live,
        "control": {
            "quarantined": control.quarantined,
            "paused": control.paused,
            "egress_isolated": control.egress_isolated,
            "quarantine_reason": control.quarantine_reason,
            "quarantine_hitl_id": control.quarantine_hitl_id,
            "lifecycle_strict": crate::services::intelligence_authority::lifecycle_auth_strict(),
        },
        "identity": {
            "character_name": snap.character_name,
            "character_purpose": snap.character_purpose,
            "has_character": snap.has_character,
            "address": snap.address,
            "address_type": snap.address_type,
        },
        "knowledge": {
            "has_last_memory": snap.has_last_memory,
            "last_memory_at_ms": snap.last_memory_at_ms,
            "last_memory_cid": snap.last_memory_cid,
            "address_relation_count": snap.relation_count,
            "has_address_identity_graph": snap.has_address_identity_graph,
            "total_packets": live.get("total_packets").cloned(),
            "active_sessions": live.get("active_sessions").cloned(),
        },
        "identity_stack": {
            "missing": snap.missing,
            "operable": snap.missing.is_empty(),
            "enforced": crate::substrate::identity_stack::identity_stack_enforce_enabled(),
            "has_address_rules_contract": snap.has_address_rules_contract,
            "has_address_hitl_contract": snap.has_address_hitl_contract,
        },
        "address_dac": dac_rows,
        "block_seals": seals,
        "pending_hitl": pending_hitl,
        "recent_denials": denials,
        "honesty": "Read-only. Dry-run only — opening this never writes a Block seal and never mints a HITL request.",
    })))
}
