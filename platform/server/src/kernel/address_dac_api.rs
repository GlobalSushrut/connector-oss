//! Operator control plane for per-address DAC (rules ≠ HITL) and Block seals.
//!
//! The kernel enforces two *different* contracts per address:
//!
//! * `address_rules_contract_v1` — capability allow / block
//! * `address_hitl_contract_v1`  — human gate none / ask / root / block
//!
//! [`crate::substrate::identity_stack`] refuses augmented actions until both
//! exist for the target address, so without these endpoints an operator has
//! no way to mint them and the node deadlocks. Everything here is
//! admin-guarded; unsealing additionally requires the kernel root passcode.
//!
//! Reads are dry-run only — the index and matrix call
//! [`address_contracts::preview`], which never persists a seal.

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
pub struct AddressQuery {
    pub address: String,
}

#[derive(Debug, Deserialize)]
pub struct RulesBody {
    pub address: String,
    #[serde(default)]
    pub default_effect: Option<String>,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub denied_tools: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct HitlBody {
    pub address: String,
    #[serde(default)]
    pub default_policy: Option<String>,
    /// tool id → none | ask | root | block
    #[serde(default)]
    pub tools: Vec<ToolPolicy>,
}

#[derive(Debug, Deserialize)]
pub struct ToolPolicy {
    pub id: String,
    pub policy: String,
}

#[derive(Debug, Deserialize)]
pub struct UnsealBody {
    pub address: String,
    pub tool: String,
    pub root_passcode: String,
}

#[derive(Debug, Deserialize)]
pub struct SimulateBody {
    pub address: String,
    #[serde(default)]
    pub tools: Vec<String>,
}

fn denied(e: Value) -> Json<Value> {
    Json(e)
}

fn contract_summary(state: &SharedState, address: &str) -> Value {
    let rules = dac::load_rules(state.as_ref(), address);
    let hitl = dac::load_hitl(state.as_ref(), address);
    let seals = dac::list_block_seals(state.as_ref(), Some(address));
    let mut missing = Vec::new();
    if rules.is_none() {
        missing.push("address_rules_contract");
    }
    if hitl.is_none() {
        missing.push("address_hitl_contract");
    }
    json!({
        "address": address,
        "has_rules_contract": rules.is_some(),
        "has_hitl_contract": hitl.is_some(),
        "default_effect": rules.as_ref().map(|r| r.default_effect.clone()),
        "default_policy": hitl.as_ref().map(|h| h.default_policy.clone()),
        "allowed_tools": rules.as_ref().map(|r| r.allowed_tools.clone()).unwrap_or_default(),
        "denied_tools": rules.as_ref().map(|r| r.denied_tools.clone()).unwrap_or_default(),
        "hitl_tools": hitl
            .as_ref()
            .map(|h| {
                h.tools
                    .iter()
                    .map(|t| json!({"id": t.id, "policy": t.policy}))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
        "block_seal_count": seals.len(),
        "missing": missing,
        "operable": missing.is_empty(),
    })
}

/// `GET /api/v1/kernel/address-dac` — every address the kernel knows about.
pub async fn get_address_dac_index(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return denied(e);
    }
    let addresses: Vec<Value> = dac::known_addresses(state.as_ref())
        .iter()
        .map(|a| contract_summary(&state, a))
        .collect();
    let incomplete = addresses
        .iter()
        .filter(|a| a.get("operable").and_then(|x| x.as_bool()) == Some(false))
        .count();
    Json(operator_envelope(json!({
        "schema": "address_dac_index.v1",
        "addresses": addresses,
        "address_count": addresses.len(),
        "incomplete_count": incomplete,
        "total_block_seals": dac::list_block_seals(state.as_ref(), None).len(),
        "posture": dac::posture_json(),
        "identity_stack_enforced": crate::substrate::identity_stack::identity_stack_enforce_enabled(),
    })))
}

/// `GET /api/v1/kernel/address-dac/contract?address=…` — both contracts + seals.
pub async fn get_address_dac_contract(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<AddressQuery>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return denied(e);
    }
    let rules = dac::load_rules(state.as_ref(), &q.address);
    let hitl = dac::load_hitl(state.as_ref(), &q.address);
    Json(operator_envelope(json!({
        "schema": "address_dac_contract.v1",
        "summary": contract_summary(&state, &q.address),
        "rules_contract": rules.as_ref().and_then(|r| serde_json::to_value(r).ok()),
        "hitl_contract": hitl.as_ref().and_then(|h| serde_json::to_value(h).ok()),
        "block_seals": dac::list_block_seals(state.as_ref(), Some(&q.address)),
        "honesty": "Rules and HITL are separate documents. An agent's own charter cannot substitute for either.",
    })))
}

/// `PUT /api/v1/kernel/address-dac/rules` — mint / replace the rules contract.
pub async fn put_address_dac_rules(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<RulesBody>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return denied(e);
    }
    let default_effect = body
        .default_effect
        .unwrap_or_else(|| "block".into())
        .trim()
        .to_ascii_lowercase();
    if !matches!(default_effect.as_str(), "allow" | "block") {
        return Json(json!({
            "ok": false,
            "error": "default_effect must be allow or block (ask belongs on the HITL contract)",
        }));
    }
    let contract = dac::AddressRulesContractV1 {
        schema: dac::RULES_SCHEMA.into(),
        address: body.address.clone(),
        default_effect,
        tools: Vec::new(),
        allowed_tools: body.allowed_tools,
        denied_tools: body.denied_tools,
        contract_version: 1,
    };
    match dac::save_rules(state.as_ref(), &contract) {
        Ok(()) => Json(operator_envelope(json!({
            "schema": "address_dac_rules_saved.v1",
            "summary": contract_summary(&state, &body.address),
            "honesty": "Rules saved. Existing Block seals are NOT lifted by a rules edit — unseal explicitly.",
        }))),
        Err(e) => Json(json!({"ok": false, "error": e})),
    }
}

/// `PUT /api/v1/kernel/address-dac/hitl` — mint / replace the HITL contract.
pub async fn put_address_dac_hitl(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<HitlBody>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return denied(e);
    }
    let default_policy = body
        .default_policy
        .unwrap_or_else(|| "ask".into())
        .trim()
        .to_ascii_lowercase();
    if !matches!(default_policy.as_str(), "none" | "ask" | "root" | "block") {
        return Json(json!({
            "ok": false,
            "error": "default_policy must be none, ask, root, or block",
        }));
    }
    let mut tools = Vec::new();
    for t in body.tools {
        let policy = t.policy.trim().to_ascii_lowercase();
        if !matches!(policy.as_str(), "none" | "ask" | "root" | "block") {
            return Json(json!({
                "ok": false,
                "error": format!("tool '{}' has invalid policy '{}'", t.id, t.policy),
            }));
        }
        tools.push(dac::AddressToolHitl { id: t.id, policy });
    }
    let contract = dac::AddressHitlContractV1 {
        schema: dac::HITL_SCHEMA.into(),
        address: body.address.clone(),
        default_policy,
        tools,
        contract_version: 1,
    };
    match dac::save_hitl(state.as_ref(), &contract) {
        Ok(()) => Json(operator_envelope(json!({
            "schema": "address_dac_hitl_saved.v1",
            "summary": contract_summary(&state, &body.address),
            "honesty": "HITL saved. HITL can never lift a kernel Block — it only gates an otherwise-allowed tool.",
        }))),
        Err(e) => Json(json!({"ok": false, "error": e})),
    }
}

/// `POST /api/v1/kernel/address-dac/simulate` — dry-run verdicts, no seals written.
pub async fn post_address_dac_simulate(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<SimulateBody>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return denied(e);
    }
    let rows: Vec<Value> = body
        .tools
        .iter()
        .map(|t| dac::preview(state.as_ref(), &body.address, t))
        .collect();
    Json(operator_envelope(json!({
        "schema": "address_dac_simulate.v1",
        "address": body.address,
        "results": rows,
        "honesty": "Dry run. No Block seal was written. A real call may seal where would_seal=true.",
    })))
}

#[derive(Debug, Deserialize)]
pub struct IdentityStackQuery {
    pub agent_pid: String,
    #[serde(default)]
    pub namespace: Option<String>,
    /// `llm.chat` | `memory.write` | `tool:<id>` | `mcp:<name>`
    #[serde(default)]
    pub op: Option<String>,
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

/// `GET /api/v1/kernel/identity-stack?agent_pid=…` — which pillar is blocking.
///
/// Read-only: [`crate::substrate::identity_stack::inspect`] never mints a HITL
/// request, so an operator can diagnose a denial without creating one.
pub async fn get_identity_stack(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Query(q): Query<IdentityStackQuery>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return denied(e);
    }
    let namespace = q.namespace.unwrap_or_else(|| "default".into());
    let op = parse_op(q.op.as_deref());
    let snap = crate::substrate::identity_stack::inspect(&state, &q.agent_pid, &namespace, &op);
    let control = crate::services::intelligence_authority::load_agent_control(&state, &q.agent_pid);

    Json(operator_envelope(json!({
        "schema": "identity_stack_inspect.v1",
        "agent_pid": q.agent_pid,
        "namespace": namespace,
        "op": op.slug(),
        "address": snap.address,
        "address_type": snap.address_type,
        "pillars": [
            {
                "id": "identity_character",
                "label": "Identity character",
                "satisfied": snap.has_character,
                "detail": snap.character_name.clone(),
                "purpose": snap.character_purpose.clone(),
                "fix": "Set a name + purpose on the agent spec or setup.",
            },
            {
                "id": "last_memory",
                "label": "Last memory",
                "satisfied": snap.has_last_memory,
                "at_ms": snap.last_memory_at_ms,
                "cid": snap.last_memory_cid.clone(),
                "fix": "Write one MemPacket for this agent.",
            },
            {
                "id": "address_relation_identity_graph",
                "label": "Address relation graph",
                "satisfied": snap.has_address_identity_graph,
                "relation_count": snap.relation_count,
                "fix": "Add a knot edge between this agent's identity and the address node.",
            },
            {
                "id": "address_rules_contract",
                "label": "Address RULES contract",
                "satisfied": snap.has_address_rules_contract,
                "fix": "PUT /api/v1/kernel/address-dac/rules",
            },
            {
                "id": "address_hitl_contract",
                "label": "Address HITL contract",
                "satisfied": snap.has_address_hitl_contract,
                "fix": "PUT /api/v1/kernel/address-dac/hitl",
            },
        ],
        "missing": snap.missing,
        "operable": snap.missing.is_empty(),
        "enforced": crate::substrate::identity_stack::identity_stack_enforce_enabled(),
        "control": {
            "quarantined": control.quarantined,
            "paused": control.paused,
            "egress_isolated": control.egress_isolated,
            "quarantine_reason": control.quarantine_reason,
            "quarantine_hitl_id": control.quarantine_hitl_id,
        },
        "lifecycle_strict": crate::services::intelligence_authority::lifecycle_auth_strict(),
        "honesty": "Rules and HITL are separate pillars. Both must exist before any augmented action.",
    })))
}

/// `POST /api/v1/kernel/address-dac/unseal` — lift a kernel Block (root passcode).
pub async fn post_address_dac_unseal(
    State(state): State<SharedState>,
    headers: HeaderMap,
    Json(body): Json<UnsealBody>,
) -> Json<Value> {
    if let Err(e) = require_admin_or_dev(&headers) {
        return denied(e);
    }
    match dac::unseal_block(
        state.as_ref(),
        &body.address,
        &body.tool,
        &body.root_passcode,
    ) {
        Ok(()) => Json(operator_envelope(json!({
            "schema": "address_dac_unseal.v1",
            "address": body.address,
            "tool": dac::canonicalize_tool(&body.tool),
            "unsealed": true,
            "summary": contract_summary(&state, &body.address),
            "honesty": "Seal removed by operator with kernel root passcode. The RULES contract still decides the next call.",
        }))),
        Err(e) => Json(json!({
            "ok": false,
            "error": e,
            "honesty": "Block is kernel-final. Neither HITL approval nor any LLM can unseal it.",
        })),
    }
}
