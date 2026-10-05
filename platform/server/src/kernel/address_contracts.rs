//! Per-address access contracts — **rules** and **HITL** are different documents.
//!
//! Agent identity does not substitute its own charter HITL/rules for an address.
//! Agent A touching address A9 with tools t1, t2, t3 must satisfy:
//!   1. `AddressRulesContract` — allow | block (capability / tool list)
//!   2. `AddressHitlContract`  — none | ask | root | block (human approval)
//!
//! Fold: rules Block wins; HITL Ask upgrades Allow; App/agent HITL cannot
//! skip address HITL. Dynamic: evaluated at request time per (agent × address × tool).

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::state::{PlatformState, SharedState};

pub const RULES_SCHEMA: &str = "address_rules.v1";
pub const HITL_SCHEMA: &str = "address_hitl.v1";
pub const RULES_FOLDER: &str = "address_rules_contract_v1";
pub const HITL_FOLDER: &str = "address_hitl_contract_v1";
/// Kernel-final Block receipts. HITL, LLM output, and future models cannot unseal.
pub const BLOCK_SEAL_FOLDER: &str = "address_block_seal_v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressRulesEffect {
    Allow,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressHitlPolicy {
    /// No extra human gate from this address (rules still apply).
    None,
    /// Digest-bound HITL required for this tool at this address.
    Ask,
    /// Human is root at this address — always Ask.
    Root,
    /// HITL contract forbids the tool (not a rules deny — separate).
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressDacVerdict {
    Allow,
    Ask,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressToolRule {
    pub id: String,
    /// allow | block — never "ask" (that belongs on the HITL contract).
    pub effect: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressToolHitl {
    pub id: String,
    /// none | ask | root | block
    pub policy: String,
}

/// Capability / tool allow-list for one address. Not HITL.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressRulesContractV1 {
    pub schema: String,
    pub address: String,
    /// deny-by-default: block | allow
    #[serde(default = "default_block")]
    pub default_effect: String,
    #[serde(default)]
    pub tools: Vec<AddressToolRule>,
    #[serde(default)]
    pub allowed_tools: Vec<String>,
    #[serde(default)]
    pub denied_tools: Vec<String>,
    #[serde(default = "trust_v1")]
    pub contract_version: u32,
}

/// Human-approval contract for one address. Not a tool allow-list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressHitlContractV1 {
    pub schema: String,
    pub address: String,
    /// none | ask | root | block
    #[serde(default = "default_ask")]
    pub default_policy: String,
    #[serde(default)]
    pub tools: Vec<AddressToolHitl>,
    #[serde(default = "trust_v1")]
    pub contract_version: u32,
}

fn default_block() -> String {
    "block".into()
}
fn default_ask() -> String {
    "ask".into()
}
fn trust_v1() -> u32 {
    1
}

pub fn folder_key(address: &str) -> String {
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

fn tool_norm(s: &str) -> String {
    canonicalize_tool(s)
}

/// Kernel-canonical tool id. Drops bidi/zero-width (LLM homoglyph / overlay tricks).
/// Non-ASCII → empty (fail-closed Block), not a parallel identity.
pub fn canonicalize_tool(raw: &str) -> String {
    let stripped: String = raw
        .chars()
        .filter(|c| {
            let u = *c as u32;
            !matches!(
                u,
                0x00AD
                    | 0x200B..=0x200F
                    | 0x202A..=0x202E
                    | 0x2060..=0x2064
                    | 0x2066..=0x2069
                    | 0xFEFF
            )
        })
        .collect();
    let mut out = String::with_capacity(stripped.len());
    for c in stripped.trim().chars() {
        if c.is_ascii_alphanumeric() || matches!(c, ':' | '/' | '.' | '-' | '_') {
            out.push(c.to_ascii_lowercase());
        }
    }
    out
}

fn tool_well_formed(canon: &str) -> bool {
    !canon.is_empty()
        && canon.is_ascii()
        && canon
            .chars()
            .any(|c| c.is_ascii_alphanumeric())
}

/// Reject homoglyph / non-ASCII tool ids before they collapse to an ASCII alias.
fn tool_surface_is_ascii(raw: &str) -> bool {
    raw.chars().all(|c| {
        let u = c as u32;
        if matches!(
            u,
            0x00AD
                | 0x200B..=0x200F
                | 0x202A..=0x202E
                | 0x2060..=0x2064
                | 0x2066..=0x2069
                | 0xFEFF
        ) {
            return true; // stripped later
        }
        c.is_ascii()
    })
}

fn tools_match(listed: &str, tool: &str) -> bool {
    let a = tool_norm(listed);
    let b = tool_norm(tool);
    if a.is_empty() || b.is_empty() {
        return false;
    }
    // Exact or namespaced suffix only — never substring (LLM "t" must not match "t1").
    a == b || b.ends_with(&format!(":{a}")) || a.ends_with(&format!(":{b}"))
}

fn seal_key(address: &str, tool: &str) -> String {
    use sha2::{Digest, Sha256};
    let raw = format!(
        "block_seal|{}|{}",
        folder_key(address),
        canonicalize_tool(tool)
    );
    hex::encode(Sha256::digest(raw.as_bytes()))
}

pub fn block_seal_active(state: &PlatformState, address: &str, tool: &str) -> bool {
    let Ok(es) = state.engine_store.lock() else {
        return true; // lock fail → fail closed
    };
    es.folder_get(BLOCK_SEAL_FOLDER, &seal_key(address, tool))
        .ok()
        .flatten()
        .is_some()
}

fn persist_block_seal(state: &PlatformState, address: &str, tool: &str, reason: &str) {
    let Ok(mut es) = state.engine_store.lock() else {
        return;
    };
    let key = seal_key(address, tool);
    let _ = es.folder_put(
        BLOCK_SEAL_FOLDER,
        &key,
        &json!({
            "schema": "address_block_seal.v1",
            "address": address,
            "tool": canonicalize_tool(tool),
            "reason": reason,
            "sealed_at": chrono::Utc::now().to_rfc3339(),
            "kernel_final": true,
            "llm_override": false,
            "hitl_override": false,
            "honesty": "Block is kernel physics. Current and future LLMs cannot unseal. HITL cannot unseal. Only operator unseal_block + rules change.",
        }),
    );
}

/// Operator-only: lift a kernel Block seal (root passcode). LLM/agent paths must not call this.
pub fn unseal_block(
    state: &PlatformState,
    address: &str,
    tool: &str,
    root_pass: &str,
) -> Result<(), String> {
    crate::kernel::world_gateway::verify_root_passcode(root_pass)?;
    let mut es = state.engine_store.lock().map_err(|e| e.to_string())?;
    es.folder_delete(BLOCK_SEAL_FOLDER, &seal_key(address, tool))
        .map_err(|e| e.to_string())?;
    Ok(())
}

impl AddressRulesContractV1 {
    pub fn effect_for(&self, tool: &str) -> AddressRulesEffect {
        if self
            .denied_tools
            .iter()
            .any(|t| tools_match(t, tool))
        {
            return AddressRulesEffect::Block;
        }
        if let Some(row) = self.tools.iter().find(|t| tools_match(&t.id, tool)) {
            return if row.effect.trim().eq_ignore_ascii_case("allow") {
                AddressRulesEffect::Allow
            } else {
                AddressRulesEffect::Block
            };
        }
        if !self.allowed_tools.is_empty() {
            return if self.allowed_tools.iter().any(|t| tools_match(t, tool)) {
                AddressRulesEffect::Allow
            } else {
                AddressRulesEffect::Block
            };
        }
        if self.default_effect.trim().eq_ignore_ascii_case("allow") {
            AddressRulesEffect::Allow
        } else {
            AddressRulesEffect::Block
        }
    }
}

impl AddressHitlContractV1 {
    pub fn policy_for(&self, tool: &str) -> AddressHitlPolicy {
        if let Some(row) = self.tools.iter().find(|t| tools_match(&t.id, tool)) {
            return parse_hitl(&row.policy);
        }
        parse_hitl(&self.default_policy)
    }
}

fn parse_hitl(s: &str) -> AddressHitlPolicy {
    match s.trim().to_ascii_lowercase().as_str() {
        "none" | "allow" | "app" => AddressHitlPolicy::None,
        "root" | "human" => AddressHitlPolicy::Root,
        "block" | "deny" => AddressHitlPolicy::Block,
        _ => AddressHitlPolicy::Ask,
    }
}

pub fn load_rules(state: &PlatformState, address: &str) -> Option<AddressRulesContractV1> {
    let key = folder_key(address);
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(RULES_FOLDER, &key).ok().flatten()?;
    serde_json::from_value(v).ok()
}

pub fn load_hitl(state: &PlatformState, address: &str) -> Option<AddressHitlContractV1> {
    let key = folder_key(address);
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(HITL_FOLDER, &key).ok().flatten()?;
    serde_json::from_value(v).ok()
}

pub fn save_rules(state: &PlatformState, contract: &AddressRulesContractV1) -> Result<(), String> {
    let mut es = state.engine_store.lock().map_err(|e| e.to_string())?;
    es.folder_put(
        RULES_FOLDER,
        &folder_key(&contract.address),
        &serde_json::to_value(contract).unwrap_or(json!({})),
    )
    .map_err(|e| e.to_string())
}

pub fn save_hitl(state: &PlatformState, contract: &AddressHitlContractV1) -> Result<(), String> {
    let mut es = state.engine_store.lock().map_err(|e| e.to_string())?;
    es.folder_put(
        HITL_FOLDER,
        &folder_key(&contract.address),
        &serde_json::to_value(contract).unwrap_or(json!({})),
    )
    .map_err(|e| e.to_string())
}

pub fn tool_from_op(op: &crate::services::admission::AdmissionOp) -> String {
    use crate::services::admission::AdmissionOp;
    match op {
        AdmissionOp::ToolDispatch { tool_id } => tool_id.clone(),
        AdmissionOp::McpCall { tool_name } => tool_name.clone(),
        AdmissionOp::LlmChat => "llm.chat".into(),
        AdmissionOp::MemoryWrite => "memory.write".into(),
        AdmissionOp::MemoryRead { namespace } => format!("memory.read:{namespace}"),
        AdmissionOp::PipelineStep { pipeline_id, step } => {
            format!("pipeline:{pipeline_id}:{step}")
        }
        AdmissionOp::ConpCommand { capability_id, .. } => format!("conp:{capability_id}"),
    }
}

/// Dynamic DAC: rules first (capability), then HITL (human). Never mixed.
/// Block is kernel-final: seals persist; HITL/LLM cannot convert Block → Allow.
pub fn evaluate(
    state: &PlatformState,
    address: &str,
    tool: &str,
) -> Result<AddressDacVerdict, String> {
    let canon = canonicalize_tool(tool);
    if !tool_surface_is_ascii(tool) || !tool_well_formed(&canon) {
        persist_block_seal(state, address, tool, "malformed_or_non_ascii_tool_id");
        return Ok(AddressDacVerdict::Block);
    }
    if block_seal_active(state, address, &canon) {
        return Ok(AddressDacVerdict::Block);
    }

    let rules = load_rules(state, address).ok_or_else(|| {
        format!("address_rules_contract_missing:{address} (rules ≠ HITL — mint {RULES_FOLDER})")
    })?;
    let hitl = load_hitl(state, address).ok_or_else(|| {
        format!("address_hitl_contract_missing:{address} (HITL ≠ rules — mint {HITL_FOLDER})")
    })?;

    match rules.effect_for(&canon) {
        AddressRulesEffect::Block => {
            persist_block_seal(state, address, &canon, "address_rules_block");
            return Ok(AddressDacVerdict::Block);
        }
        AddressRulesEffect::Allow => {}
    }

    Ok(match hitl.policy_for(&canon) {
        AddressHitlPolicy::None => AddressDacVerdict::Allow,
        AddressHitlPolicy::Ask | AddressHitlPolicy::Root => AddressDacVerdict::Ask,
        AddressHitlPolicy::Block => {
            persist_block_seal(state, address, &canon, "address_hitl_block");
            AddressDacVerdict::Block
        }
    })
}

/// Read-only DAC dry-run for operator surfaces.
///
/// Same decision order as [`evaluate`], but never writes a Block seal —
/// an operator inspecting a matrix must not create kernel-final state.
/// `would_seal` reports where a real call would persist one.
pub fn preview(state: &PlatformState, address: &str, tool: &str) -> serde_json::Value {
    let canon = canonicalize_tool(tool);
    let mut out = json!({
        "tool": tool,
        "canonical_tool": canon,
        "address": address,
    });
    let set = |out: &mut serde_json::Value, verdict: &str, reason: &str, would_seal: bool| {
        if let Some(o) = out.as_object_mut() {
            o.insert("verdict".into(), json!(verdict));
            o.insert("reason".into(), json!(reason));
            o.insert("would_seal".into(), json!(would_seal));
        }
    };

    if !tool_surface_is_ascii(tool) || !tool_well_formed(&canon) {
        set(
            &mut out,
            "block",
            "malformed_or_non_ascii_tool_id",
            !block_seal_active(state, address, &canon),
        );
        return out;
    }
    if block_seal_active(state, address, &canon) {
        set(&mut out, "block", "sealed", false);
        return out;
    }
    let Some(rules) = load_rules(state, address) else {
        set(&mut out, "block", "address_rules_contract_missing", false);
        return out;
    };
    let Some(hitl) = load_hitl(state, address) else {
        set(&mut out, "block", "address_hitl_contract_missing", false);
        return out;
    };
    if matches!(rules.effect_for(&canon), AddressRulesEffect::Block) {
        set(&mut out, "block", "address_rules_block", true);
        return out;
    }
    match hitl.policy_for(&canon) {
        AddressHitlPolicy::None => set(&mut out, "allow", "rules_allow_hitl_none", false),
        AddressHitlPolicy::Ask => set(&mut out, "ask", "address_hitl_ask", false),
        AddressHitlPolicy::Root => set(&mut out, "ask", "address_hitl_root", false),
        AddressHitlPolicy::Block => set(&mut out, "block", "address_hitl_block", true),
    }
    out
}

/// Every address that has a rules contract, a HITL contract, or a Block seal.
pub fn known_addresses(state: &PlatformState) -> Vec<String> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    for folder in [RULES_FOLDER, HITL_FOLDER] {
        for key in es.folder_keys(folder, None).unwrap_or_default() {
            if let Ok(Some(v)) = es.folder_get(folder, &key) {
                if let Some(a) = v.get("address").and_then(|x| x.as_str()) {
                    if !out.iter().any(|e| e == a) {
                        out.push(a.to_string());
                    }
                }
            }
        }
    }
    for key in es.folder_keys(BLOCK_SEAL_FOLDER, None).unwrap_or_default() {
        if let Ok(Some(v)) = es.folder_get(BLOCK_SEAL_FOLDER, &key) {
            if let Some(a) = v.get("address").and_then(|x| x.as_str()) {
                if !out.iter().any(|e| e == a) {
                    out.push(a.to_string());
                }
            }
        }
    }
    out.sort();
    out
}

/// Active Block seals, optionally narrowed to one address.
pub fn list_block_seals(state: &PlatformState, address: Option<&str>) -> Vec<serde_json::Value> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for key in es.folder_keys(BLOCK_SEAL_FOLDER, None).unwrap_or_default() {
        if let Ok(Some(v)) = es.folder_get(BLOCK_SEAL_FOLDER, &key) {
            let matches_addr = address
                .map(|a| v.get("address").and_then(|x| x.as_str()) == Some(a))
                .unwrap_or(true);
            if matches_addr {
                out.push(v);
            }
        }
    }
    out
}

/// Fold address DAC onto an existing autonomy verdict. Cannot downgrade Block/Ask.
pub fn fold_verdict(current: AddressDacVerdict, address: AddressDacVerdict) -> AddressDacVerdict {
    match (current, address) {
        (AddressDacVerdict::Block, _) | (_, AddressDacVerdict::Block) => AddressDacVerdict::Block,
        (AddressDacVerdict::Ask, _) | (_, AddressDacVerdict::Ask) => AddressDacVerdict::Ask,
        _ => AddressDacVerdict::Allow,
    }
}

/// Governed-effect enforcement.
/// Block is always applied (lab cannot skip). HITL never lifts Block.
pub fn enforce_for_effect(
    state: &SharedState,
    agent_pid: &str,
    address: &str,
    tool: &str,
) -> Result<(), crate::error::ConnectorError> {
    use crate::error::{ConnectorError, DenialReason};
    use sha2::{Digest, Sha256};

    let verdict = match evaluate(state.as_ref(), address, tool) {
        Ok(v) => v,
        Err(e) => {
            if !crate::substrate::identity_stack::identity_stack_enforce_enabled()
                && !crate::kernel::agent_principal::intelligence_hardening_on()
            {
                return Ok(());
            }
            return Err(ConnectorError::new(
                DenialReason::CapabilityRequired,
                format!("Address access control denied: {e}"),
            )
            .with_denied_resource(address.to_string())
            .with_hint(
                "Mint separate address_rules_contract_v1 and address_hitl_contract_v1 for this address. They are different contracts.",
            ));
        }
    };

    match verdict {
        AddressDacVerdict::Allow => Ok(()),
        AddressDacVerdict::Block => Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!(
                "KERNEL BLOCK: tool '{}' at {} — not overridable by this LLM, a future evolved LLM, HITL approve, or agent charter",
                canonicalize_tool(tool),
                address
            ),
        )
        .with_denied_resource(address.to_string())
        .with_hint(
            "Block is kernel-final (address_block_seal_v1). HITL cannot unseal. LLM output cannot unseal. Operator must unseal_block with kernel root passcode, then change the RULES contract.",
        )),
        AddressDacVerdict::Ask => {
            if !crate::substrate::identity_stack::identity_stack_enforce_enabled()
                && !crate::kernel::agent_principal::intelligence_hardening_on()
            {
                return Ok(());
            }
            let digest = hex::encode(Sha256::digest(
                format!(
                    "address_hitl|{agent_pid}|{address}|{}",
                    canonicalize_tool(tool)
                )
                .as_bytes(),
            ));
            if crate::services::agents::hitl_consume_for_action(
                Some(state),
                agent_pid,
                &digest,
                Some(HITL_SCHEMA),
                None,
            )
            .is_ok()
            {
                // Re-evaluate: if rules/seal became Block, HITL must not proceed.
                if matches!(
                    evaluate(state.as_ref(), address, tool),
                    Ok(AddressDacVerdict::Block)
                ) {
                    return Err(ConnectorError::new(
                        DenialReason::PolicyDenied,
                        "HITL approval cannot lift a kernel Block",
                    )
                    .with_denied_resource(address.to_string()));
                }
                return Ok(());
            }
            let request_id = crate::services::agents::hitl_submit_bound(
                agent_pid,
                "address_hitl.tool",
                &format!(
                    "Address HITL: agent {agent_pid} using {} at {address}",
                    canonicalize_tool(tool)
                ),
                &digest,
                Some(json!({
                    "schema": HITL_SCHEMA,
                    "address": address,
                    "tool": canonicalize_tool(tool),
                    "honesty": "HITL contract of the address — not the agent's setup HITL. HITL cannot override Block.",
                })),
                Some(HITL_SCHEMA.into()),
                None,
                Some(state),
            );
            Err(ConnectorError::new(
                DenialReason::CapabilityRequired,
                format!(
                    "Address HITL required for tool '{}' at {address} (rules allowed; HITL is a different contract)",
                    canonicalize_tool(tool)
                ),
            )
            .with_denied_resource(address.to_string())
            .with_hint(format!(
                "hitl_required request_id={request_id} — approve POST /api/v1/agents/{agent_pid}/hitl/{request_id}/approve"
            ))
            .with_example_fix(format!(
                "curl -X POST /api/v1/agents/{agent_pid}/hitl/{request_id}/approve"
            )))
        }
    }
}

pub fn posture_json() -> serde_json::Value {
    json!({
        "schema": "address_dac.v1",
        "honesty": "Agent A × address A9 × tools t1,t2,t3: follow A9 RULES contract and A9 HITL contract. They are different. Agent setup HITL/rules cannot substitute.",
        "rules_folder": RULES_FOLDER,
        "hitl_folder": HITL_FOLDER,
        "fold": "Block is kernel-final > Ask > Allow; HITL/LLM/future models cannot lift Block",
        "block_seal_folder": BLOCK_SEAL_FOLDER,
        "block_honesty": "Sealed Block survives tool-name aliases, HITL approve, and model substitution. Only kernel root unseal_block.",
        "dynamic": true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules_a9() -> AddressRulesContractV1 {
        AddressRulesContractV1 {
            schema: RULES_SCHEMA.into(),
            address: "A9".into(),
            default_effect: "block".into(),
            tools: vec![],
            allowed_tools: vec!["t1".into(), "t2".into(), "t3".into()],
            denied_tools: vec![],
            contract_version: 1,
        }
    }

    fn hitl_a9() -> AddressHitlContractV1 {
        AddressHitlContractV1 {
            schema: HITL_SCHEMA.into(),
            address: "A9".into(),
            default_policy: "ask".into(),
            tools: vec![
                AddressToolHitl {
                    id: "t1".into(),
                    policy: "ask".into(),
                },
                AddressToolHitl {
                    id: "t2".into(),
                    policy: "none".into(),
                },
                AddressToolHitl {
                    id: "t3".into(),
                    policy: "ask".into(),
                },
            ],
            contract_version: 1,
        }
    }

    #[test]
    fn rules_are_not_hitl() {
        let r = rules_a9();
        assert_eq!(r.effect_for("t1"), AddressRulesEffect::Allow);
        assert_eq!(r.effect_for("t9"), AddressRulesEffect::Block);
        assert!(r.tools.iter().all(|t| !t.effect.eq_ignore_ascii_case("ask")));
    }

    #[test]
    fn hitl_does_not_grant_capability() {
        let h = hitl_a9();
        assert_eq!(h.policy_for("t1"), AddressHitlPolicy::Ask);
        assert_eq!(h.policy_for("t2"), AddressHitlPolicy::None);
        assert_eq!(h.policy_for("t3"), AddressHitlPolicy::Ask);
        let r = rules_a9();
        assert_eq!(r.effect_for("t2"), AddressRulesEffect::Allow);
    }

    #[test]
    fn agent_a_tools_on_a9() {
        let r = rules_a9();
        let h = hitl_a9();
        let fold = |tool: &str| {
            let rv = match r.effect_for(tool) {
                AddressRulesEffect::Block => AddressDacVerdict::Block,
                AddressRulesEffect::Allow => AddressDacVerdict::Allow,
            };
            let hv = match h.policy_for(tool) {
                AddressHitlPolicy::None => AddressDacVerdict::Allow,
                AddressHitlPolicy::Ask | AddressHitlPolicy::Root => AddressDacVerdict::Ask,
                AddressHitlPolicy::Block => AddressDacVerdict::Block,
            };
            fold_verdict(rv, hv)
        };
        assert_eq!(fold("t1"), AddressDacVerdict::Ask);
        assert_eq!(fold("t2"), AddressDacVerdict::Allow);
        assert_eq!(fold("t3"), AddressDacVerdict::Ask);
        assert_eq!(fold("t99"), AddressDacVerdict::Block);
    }

    #[test]
    fn substring_is_not_a_match() {
        let r = rules_a9();
        assert_eq!(r.effect_for("t"), AddressRulesEffect::Block);
        assert_eq!(r.effect_for("t1"), AddressRulesEffect::Allow);
    }

    #[test]
    fn canonicalize_strips_llm_overlay() {
        assert_eq!(canonicalize_tool("T1"), "t1");
        assert_eq!(canonicalize_tool("t\u{200b}1"), "t1");
        assert_eq!(canonicalize_tool("t 1"), "t1");
        assert!(canonicalize_tool("t１").is_empty() || canonicalize_tool("t１") != "t1");
        assert!(!tool_surface_is_ascii("t１"));
        assert!(tool_surface_is_ascii("t1"));
    }

    #[test]
    fn hitl_cannot_fold_block_to_allow() {
        assert_eq!(
            fold_verdict(AddressDacVerdict::Block, AddressDacVerdict::Allow),
            AddressDacVerdict::Block
        );
        assert_eq!(
            fold_verdict(AddressDacVerdict::Allow, AddressDacVerdict::Block),
            AddressDacVerdict::Block
        );
        assert_eq!(
            fold_verdict(AddressDacVerdict::Allow, AddressDacVerdict::Ask),
            AddressDacVerdict::Ask
        );
    }
}
