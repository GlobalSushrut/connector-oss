//! TG-1 / TG-2 — Action-bound admission (digest HITL) + AutonomyGateway.
//!
//! Military/production bar: mind is a havoc oracle; the kernel admits typed actions only.
//! Approvals bind to `action_digest` (SHA-256 over canonical JSON) and are fail-closed.

use sha2::{Digest, Sha256};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::kernel::agent_principal;
use crate::quanta_polar;
use crate::state::{PlatformState, SharedState};

pub const ACTION_BINDING_SCHEMA: &str = "connector.action_binding.v1";
pub const AUTONOMY_GATEWAY_SCHEMA: &str = "connector.autonomy_gateway.v1";

/// Exact executable request that may be admitted (TG-1 ActionBinding).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionBinding {
    pub schema_version: String,
    pub operation: String,
    pub agent_pid: String,
    pub principal_id: Option<String>,
    pub target: ActionTarget,
    pub parameters: Value,
    pub contract_digest: Option<String>,
    pub policy_version: String,
    /// Optional semantic effect intent (expected/actual delta). Digest includes this when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effect_intent: Option<crate::substrate::effect_intent::EffectIntent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ActionTarget {
    pub tool_name: String,
    pub tool_schema_version: String,
    pub resource: String,
}

impl ActionBinding {
    pub fn new(
        agent_pid: impl Into<String>,
        operation: impl Into<String>,
        tool_name: impl Into<String>,
        resource: impl Into<String>,
        parameters: Value,
        contract_digest: Option<String>,
        policy_version: impl Into<String>,
        principal_id: Option<String>,
    ) -> Self {
        Self {
            schema_version: "1.0".into(),
            operation: operation.into(),
            agent_pid: agent_pid.into(),
            principal_id,
            target: ActionTarget {
                tool_name: tool_name.into(),
                tool_schema_version: "1".into(),
                resource: resource.into(),
            },
            parameters,
            contract_digest,
            policy_version: policy_version.into(),
            effect_intent: None,
        }
    }

    pub fn digest_hex(&self) -> String {
        let canonical = canonical_json(&serde_json::to_value(self).unwrap_or(Value::Null));
        let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
        format!("{:x}", Sha256::digest(&bytes))
    }

    /// Attach semantic EffectIntent (material param change → new digest).
    pub fn with_effect_intent(
        mut self,
        intent: crate::substrate::effect_intent::EffectIntent,
    ) -> Self {
        self.effect_intent = Some(intent);
        self
    }
}

/// RFC 8785-style-ish canonicalization: sort object keys recursively.
/// Good enough for binding equality; not a full JCS library.
pub fn canonical_json(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                if let Some(child) = map.get(k) {
                    out.insert(k.clone(), canonical_json(child));
                }
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(canonical_json).collect()),
        other => other.clone(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AutonomyVerdict {
    Allow,
    Ask,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AutonomyDecision {
    pub schema: String,
    pub verdict: AutonomyVerdict,
    pub reason_code: String,
    pub action_digest: String,
    pub policy_version: String,
    pub risk_class: String,
}

/// Deterministic Allow | Ask | Block (TG-2 Phase A).
pub fn autonomy_decide(
    state: &PlatformState,
    binding: &ActionBinding,
    risk_class: &str,
) -> AutonomyDecision {
    let digest = binding.digest_hex();
    let policy_version = binding.policy_version.clone();

    // Hard block: denied operations / missing contract under harden.
    if let Err(e) = agent_principal::require_contract_action(
        state,
        &binding.agent_pid,
        &binding.operation,
        &binding.target.resource,
    ) {
        return AutonomyDecision {
            schema: AUTONOMY_GATEWAY_SCHEMA.into(),
            verdict: AutonomyVerdict::Block,
            reason_code: e,
            action_digest: digest,
            policy_version,
            risk_class: risk_class.into(),
        };
    }

    let contract = agent_principal::load_contract(state, &binding.agent_pid);
    if let Some(ref c) = contract {
        if !quanta_polar::contract_allows_action(c, &binding.operation, &binding.target.resource)
        {
            return AutonomyDecision {
                schema: AUTONOMY_GATEWAY_SCHEMA.into(),
                verdict: AutonomyVerdict::Block,
                reason_code: "contract_denied".into(),
                action_digest: digest,
                policy_version,
                risk_class: risk_class.into(),
            };
        }
    } else if agent_principal::intelligence_hardening_on() {
        return AutonomyDecision {
            schema: AUTONOMY_GATEWAY_SCHEMA.into(),
            verdict: AutonomyVerdict::Block,
            reason_code: "contract_required".into(),
            action_digest: digest,
            policy_version,
            risk_class: risk_class.into(),
        };
    }

    finish_autonomy(
        state,
        binding,
        risk_class,
        digest,
        policy_version,
        contract,
        "charter_allow",
    )
}

/// Registration creates the contract. A missing contract is not a block on that call.
/// An existing contract can still deny the action. HITL still asks.
pub fn autonomy_decide_register(
    state: &PlatformState,
    binding: &ActionBinding,
    risk_class: &str,
) -> AutonomyDecision {
    let digest = binding.digest_hex();
    let policy_version = binding.policy_version.clone();
    let contract = agent_principal::load_contract(state, &binding.agent_pid);
    if let Some(ref c) = contract {
        if !quanta_polar::contract_allows_action(c, &binding.operation, &binding.target.resource)
        {
            return AutonomyDecision {
                schema: AUTONOMY_GATEWAY_SCHEMA.into(),
                verdict: AutonomyVerdict::Block,
                reason_code: "contract_denied".into(),
                action_digest: digest,
                policy_version,
                risk_class: risk_class.into(),
            };
        }
    }
    let allow_reason = if contract.is_none() {
        "register_mints_the_first_contract"
    } else {
        "charter_allow"
    };
    finish_autonomy(
        state,
        binding,
        risk_class,
        digest,
        policy_version,
        contract,
        allow_reason,
    )
}

fn finish_autonomy(
    state: &PlatformState,
    binding: &ActionBinding,
    risk_class: &str,
    digest: String,
    policy_version: String,
    contract: Option<connector_trust::AgentContractV2>,
    allow_reason: &str,
) -> AutonomyDecision {
    let hitl_ask = hitl_policy_requires_ask(state, &binding.agent_pid, risk_class);
    // "tool" alone is not irreversible — HitlPolicyV2::Tool drives Ask via hitl_ask.
    let high_risk = matches!(
        risk_class,
        "high" | "irreversible" | "egress" | "shell" | "fabric" | "money" | "write_prod" | "export"
    );
    // TG-3: irreversible requires Ask unless charter lists `no_compensate`.
    let no_compensate = contract.as_ref().map(contract_allows_no_compensate).unwrap_or(false);
    let irreversible_needs_ask =
        risk_class == "irreversible" && !no_compensate && !hitl_ask;

    if hitl_ask
        || irreversible_needs_ask
        || (high_risk && hitl_enforce_or_tool_policy(state, &binding.agent_pid))
    {
        return AutonomyDecision {
            schema: AUTONOMY_GATEWAY_SCHEMA.into(),
            verdict: AutonomyVerdict::Ask,
            reason_code: if irreversible_needs_ask {
                "irreversible_requires_ask_or_no_compensate".into()
            } else if hitl_ask {
                "hitl_policy_ask".into()
            } else {
                "high_risk_ask".into()
            },
            action_digest: digest,
            policy_version,
            risk_class: risk_class.into(),
        };
    }

    AutonomyDecision {
        schema: AUTONOMY_GATEWAY_SCHEMA.into(),
        verdict: AutonomyVerdict::Allow,
        reason_code: allow_reason.into(),
        action_digest: digest,
        policy_version,
        risk_class: risk_class.into(),
    }
}

/// Fold admission layer onto charter decision. App never downgrades Ask/Block.
pub fn fold_admission_layer(
    mut decision: AutonomyDecision,
    admit: &crate::kernel::admission_layers::WorldAdmit,
) -> AutonomyDecision {
    use crate::kernel::admission_layers::{AdmissionLayer, WorldAdmit};
    match admit {
        WorldAdmit::LegacyCharter => decision,
        WorldAdmit::Layer(AdmissionLayer::App) => {
            if decision.verdict == AutonomyVerdict::Allow {
                decision.reason_code = "app_layer_justified_allow".into();
            }
            decision
        }
        WorldAdmit::Layer(AdmissionLayer::Cone) => {
            if decision.verdict == AutonomyVerdict::Allow {
                decision.verdict = AutonomyVerdict::Ask;
                decision.reason_code = "cone_augmented_ask".into();
            }
            decision
        }
        WorldAdmit::Layer(AdmissionLayer::Root) => {
            if decision.verdict != AutonomyVerdict::Block {
                decision.verdict = AutonomyVerdict::Ask;
                decision.reason_code = "root_hitl_ask".into();
            }
            decision
        }
    }
}

fn contract_allows_no_compensate(c: &connector_trust::AgentContractV2) -> bool {
    c.capabilities
        .iter()
        .any(|x| x == "no_compensate" || x.ends_with(":no_compensate"))
}

fn hitl_enforce_or_tool_policy(state: &PlatformState, agent_pid: &str) -> bool {
    if crate::services::admission::hitl_policy_enforce_enabled() {
        return true;
    }
    hitl_policy_requires_ask(state, agent_pid, "tool")
}

// ── MONITOR rates (process-local; TG-2) ───────────────────────────────────

use std::sync::atomic::{AtomicU64, Ordering};

static GW_ALLOW: AtomicU64 = AtomicU64::new(0);
static GW_ASK: AtomicU64 = AtomicU64::new(0);
static GW_BLOCK: AtomicU64 = AtomicU64::new(0);

pub fn record_gateway_verdict(v: AutonomyVerdict) {
    match v {
        AutonomyVerdict::Allow => {
            GW_ALLOW.fetch_add(1, Ordering::Relaxed);
        }
        AutonomyVerdict::Ask => {
            GW_ASK.fetch_add(1, Ordering::Relaxed);
        }
        AutonomyVerdict::Block => {
            GW_BLOCK.fetch_add(1, Ordering::Relaxed);
        }
    }
}

pub fn gateway_rates_snapshot() -> Value {
    json!({
        "schema": "connector.autonomy_gateway.rates.v1",
        "allow": GW_ALLOW.load(Ordering::Relaxed),
        "ask": GW_ASK.load(Ordering::Relaxed),
        "block": GW_BLOCK.load(Ordering::Relaxed),
    })
}

/// Build binding for MCP tool dispatch (shared by tools + gateway).
pub fn binding_for_tool(
    state: &PlatformState,
    agent_pid: &str,
    bridge_id: &str,
    tool_name: &str,
    parameters: &Value,
) -> ActionBinding {
    let contract = agent_principal::load_contract(state, agent_pid);
    let contract_digest = contract
        .as_ref()
        .map(|c| c.contract_digest_sha256.clone());
    let policy_version = contract
        .as_ref()
        .map(|c| c.contract_version.to_string())
        .unwrap_or_else(|| "none".into());
    let principal_id = agent_principal::load_principal(state, agent_pid).map(|p| p.principal_id);
    ActionBinding::new(
        agent_pid.to_string(),
        "tool.dispatch",
        tool_name.to_string(),
        format!("{bridge_id}:{tool_name}"),
        parameters.clone(),
        contract_digest,
        policy_version,
        principal_id,
    )
}

/// Admit tool via gateway; on Ask, try consume approved digest-bound HITL.
/// Returns Ok(()) to proceed, Err(json) to return to caller.
pub fn admit_tool_or_ask(
    state: &SharedState,
    agent_pid: &str,
    bridge_id: &str,
    tool_name: &str,
    parameters: &Value,
) -> Result<(), Value> {
    // Enhance existing charter gate: declared IntelligenceSpec skills bound the tool surface.
    if let Err(e) = crate::kernel::intelligence_spec::assert_bound_skill_allows(
        state.as_ref(),
        agent_pid,
        "tool",
        tool_name,
    ) {
        record_gateway_verdict(AutonomyVerdict::Block);
        return Err(json!({
            "error": "bound_skill_denied",
            "denial_reason": e,
            "bridge_id": bridge_id,
            "tool": tool_name,
            "honesty": "Declared bound_skills restrict tools (not markdown packs)",
        }));
    }
    if let Err(e) = crate::kernel::address_cage::assert_agent_not_host_identity(agent_pid) {
        record_gateway_verdict(AutonomyVerdict::Block);
        return Err(json!({
            "error": "host_identity_forbidden",
            "denial_reason": e,
            "tool": tool_name,
            "honesty": "A hosted agent on this machine is not the host USER/HOME/uid. Mint a Connector principal.",
        }));
    }
    let binding = binding_for_tool(state.as_ref(), agent_pid, bridge_id, tool_name, parameters);
    let risk = infer_risk_class(&binding.operation, tool_name);
    let mut decision = autonomy_decide(state.as_ref(), &binding, risk);
    let cage = crate::kernel::address_cage::resolve_tool_address(
        agent_pid,
        bridge_id,
        tool_name,
        parameters,
    );
    // Own NS FS is identity home (not outer world). Everything else is an address grant —
    // this computer, APIs, MCP tools, IoT, robots.
    if !cage.self_nsfs {
        match crate::kernel::admission_layers::admit_world(
            state.as_ref(),
            agent_pid,
            &cage.address,
            tool_name,
        ) {
            Ok(w) => decision = fold_admission_layer(decision, &w),
            Err(e) => {
                record_gateway_verdict(AutonomyVerdict::Block);
                return Err(json!({
                    "error": "world_grant_denied",
                    "denial_reason": e,
                    "tool": tool_name,
                    "entity_id": cage.address,
                    "address_type": cage.address_type,
                    "same_machine": cage.same_machine,
                    "honesty": "Outer world is an address cage. Same machine is still local:host / host_fs / host_proc — not ambient host authority. Cone/root Ask until HITL; App Allow only if justified.",
                }));
            }
        }
        match crate::kernel::address_contracts::evaluate(
            state.as_ref(),
            &cage.address,
            tool_name,
        ) {
            Ok(crate::kernel::address_contracts::AddressDacVerdict::Block) => {
                decision.verdict = AutonomyVerdict::Block;
                decision.reason_code = "address_rules_or_hitl_block".into();
            }
            Ok(crate::kernel::address_contracts::AddressDacVerdict::Ask) => {
                if decision.verdict == AutonomyVerdict::Allow {
                    decision.verdict = AutonomyVerdict::Ask;
                    decision.reason_code = "address_hitl_ask".into();
                }
            }
            Ok(crate::kernel::address_contracts::AddressDacVerdict::Allow) => {}
            Err(e) => {
                if crate::kernel::agent_principal::intelligence_hardening_on()
                    || crate::substrate::identity_stack::identity_stack_enforce_enabled()
                {
                    record_gateway_verdict(AutonomyVerdict::Block);
                    return Err(json!({
                        "error": "address_contract_required",
                        "denial_reason": e,
                        "tool": tool_name,
                        "entity_id": cage.address,
                        "honesty": "Address RULES and address HITL are different contracts. Agent setup HITL/rules cannot substitute. Agent A using t1,t2,t3 at A9 must follow A9's contracts.",
                    }));
                }
            }
        }
    }
    record_gateway_verdict(decision.verdict);

    match decision.verdict {
        AutonomyVerdict::Allow => {
            if let Err(e) = crate::kernel::decision_trace::append_trace_result(
                state.as_ref(),
                agent_pid,
                crate::kernel::decision_trace::TraceAppendOpts {
                    gateway: "allow".into(),
                    action_digest: Some(decision.action_digest.clone()),
                    outcome: format!("tool:{bridge_id}:{tool_name}"),
                    policy_version: Some(decision.policy_version.clone()),
                    ..Default::default()
                },
            ) {
                if crate::kernel::agent_principal::intelligence_hardening_on()
                    || crate::connector_profile::is_productionish_env()
                {
                    return Err(json!({
                        "error": "decision_trace_persist_failed",
                        "denial_reason": e,
                        "bridge_id": bridge_id,
                        "tool": tool_name,
                    }));
                }
            }
            Ok(())
        }
        AutonomyVerdict::Block => {
            crate::kernel::decision_trace::append_trace(
                state.as_ref(),
                agent_pid,
                crate::kernel::decision_trace::TraceAppendOpts {
                    gateway: "block".into(),
                    action_digest: Some(decision.action_digest.clone()),
                    outcome: format!("blocked:{}", decision.reason_code),
                    policy_version: Some(decision.policy_version.clone()),
                    ..Default::default()
                },
            );
            if crate::substrate::probabilistic_llm::distrust_enforced() {
                return Err(crate::substrate::probabilistic_llm::apply_denial(
                    state,
                    agent_pid,
                    crate::substrate::probabilistic_llm::DenialClass::Rule,
                    "parameters",
                    &format!("autonomy_gateway_block: {}", decision.reason_code),
                ));
            }
            Err(json!({
            "error": "autonomy_gateway_block",
            "denial_reason": decision.reason_code,
            "action_digest": decision.action_digest,
            "policy_version": decision.policy_version,
            "risk_class": decision.risk_class,
            "gateway": decision_json(&decision),
            "bridge_id": bridge_id,
            "tool": tool_name,
            "honesty": "TG-2 Block — deterministic charter/policy deny",
        }))
        }
        AutonomyVerdict::Ask => {
            // Consume one-time approved resolution for this exact digest.
            match crate::services::agents::hitl_consume_for_action(
                Some(state),
                agent_pid,
                &decision.action_digest,
                Some(binding.policy_version.as_str()),
                binding.contract_digest.as_deref(),
            ) {
                Ok(resolution) => {
                    crate::kernel::decision_trace::append_trace(
                        state.as_ref(),
                        agent_pid,
                        crate::kernel::decision_trace::TraceAppendOpts {
                            gateway: "allow".into(),
                            action_digest: Some(decision.action_digest.clone()),
                            approval_resolution_id: resolution.resolution_id.clone(),
                            outcome: format!("tool_after_hitl:{bridge_id}:{tool_name}"),
                            policy_version: Some(decision.policy_version.clone()),
                            ..Default::default()
                        },
                    );
                    Ok(())
                }
                Err(_) => {
                    let description = format!(
                        "Approve tool {}.{} (digest {})",
                        bridge_id,
                        tool_name,
                        &decision.action_digest[..decision.action_digest.len().min(16)]
                    );
                    let request_id = crate::services::agents::hitl_submit_bound(
                        agent_pid,
                        &binding.operation,
                        &description,
                        &decision.action_digest,
                        Some(serde_json::to_value(&binding).unwrap_or(Value::Null)),
                        Some(binding.policy_version.clone()),
                        binding.contract_digest.clone(),
                        Some(state),
                    );
                    crate::kernel::decision_trace::append_trace(
                        state.as_ref(),
                        agent_pid,
                        crate::kernel::decision_trace::TraceAppendOpts {
                            gateway: "ask".into(),
                            action_digest: Some(decision.action_digest.clone()),
                            outcome: format!("hitl_required:{request_id}"),
                            policy_version: Some(decision.policy_version.clone()),
                            ..Default::default()
                        },
                    );
                    Err(json!({
                        "error": "hitl_required",
                        "denial_reason": "autonomy_gateway_ask",
                        "action_digest": decision.action_digest,
                        "request_id": request_id,
                        "policy_version": decision.policy_version,
                        "risk_class": decision.risk_class,
                        "gateway": decision_json(&decision),
                        "bridge_id": bridge_id,
                        "tool": tool_name,
                        "approve_url": format!(
                            "/api/v1/agents/{agent_pid}/hitl/{request_id}/approve"
                        ),
                        "honesty": "TG-2 Ask — suspended admission until digest-bound HITL approve + consume",
                    }))
                }
            }
        }
    }
}

/// TG-2: admit Talk / llm.chat via AutonomyGateway (same membrane as tools).
/// Digest binds namespace + content hash (not raw prompt) for HITL revalidation.
pub fn binding_for_talk(
    state: &PlatformState,
    agent_pid: &str,
    namespace: &str,
    content_sha256: &str,
) -> ActionBinding {
    let contract = agent_principal::load_contract(state, agent_pid);
    let contract_digest = contract
        .as_ref()
        .map(|c| c.contract_digest_sha256.clone());
    let policy_version = contract
        .as_ref()
        .map(|c| c.contract_version.to_string())
        .unwrap_or_else(|| "0".into());
    let principal_id = agent_principal::load_principal(state, agent_pid).map(|p| p.principal_id);
    ActionBinding::new(
        agent_pid,
        "llm.chat",
        "talk",
        namespace,
        json!({
            "namespace": namespace,
            "content_sha256": content_sha256,
        }),
        contract_digest,
        policy_version,
        principal_id,
    )
}

/// Admit Talk via gateway; on Ask, try consume approved digest-bound HITL.
pub fn admit_talk_or_ask(
    state: &SharedState,
    agent_pid: &str,
    namespace: &str,
    content_for_digest: &str,
) -> Result<(), Value> {
    let content_sha256 = format!("{:x}", Sha256::digest(content_for_digest.as_bytes()));
    let binding = binding_for_talk(state.as_ref(), agent_pid, namespace, &content_sha256);
    // Talk is low-risk by default; HitlPolicy::AllMaterial still Ask.
    let risk = "llm";
    let decision = autonomy_decide(state.as_ref(), &binding, risk);
    record_gateway_verdict(decision.verdict);

    match decision.verdict {
        AutonomyVerdict::Allow => {
            crate::kernel::decision_trace::append_trace(
                state.as_ref(),
                agent_pid,
                crate::kernel::decision_trace::TraceAppendOpts {
                    gateway: "allow".into(),
                    action_digest: Some(decision.action_digest.clone()),
                    outcome: "talk:llm.chat".into(),
                    policy_version: Some(decision.policy_version.clone()),
                    message_type: Some("llm.chat".into()),
                    ..Default::default()
                },
            );
            Ok(())
        }
        AutonomyVerdict::Block => {
            crate::kernel::decision_trace::append_trace(
                state.as_ref(),
                agent_pid,
                crate::kernel::decision_trace::TraceAppendOpts {
                    gateway: "block".into(),
                    action_digest: Some(decision.action_digest.clone()),
                    outcome: format!("blocked:{}", decision.reason_code),
                    policy_version: Some(decision.policy_version.clone()),
                    message_type: Some("llm.chat".into()),
                    ..Default::default()
                },
            );
            Err(json!({
                "error": "autonomy_gateway_block",
                "denial_reason": decision.reason_code,
                "action_digest": decision.action_digest,
                "policy_version": decision.policy_version,
                "risk_class": decision.risk_class,
                "gateway": decision_json(&decision),
                "honesty": "TG-2 Talk Block — charter/policy deny",
            }))
        }
        AutonomyVerdict::Ask => {
            match crate::services::agents::hitl_consume_for_action(
                Some(state),
                agent_pid,
                &decision.action_digest,
                Some(binding.policy_version.as_str()),
                binding.contract_digest.as_deref(),
            ) {
                Ok(resolution) => {
                    crate::kernel::decision_trace::append_trace(
                        state.as_ref(),
                        agent_pid,
                        crate::kernel::decision_trace::TraceAppendOpts {
                            gateway: "allow".into(),
                            action_digest: Some(decision.action_digest.clone()),
                            approval_resolution_id: resolution.resolution_id.clone(),
                            outcome: "talk_after_hitl:llm.chat".into(),
                            policy_version: Some(decision.policy_version.clone()),
                            message_type: Some("llm.chat".into()),
                            ..Default::default()
                        },
                    );
                    Ok(())
                }
                Err(_) => {
                    let description = format!(
                        "Approve Talk llm.chat (digest {})",
                        &decision.action_digest[..decision.action_digest.len().min(16)]
                    );
                    let request_id = crate::services::agents::hitl_submit_bound(
                        agent_pid,
                        &binding.operation,
                        &description,
                        &decision.action_digest,
                        Some(serde_json::to_value(&binding).unwrap_or(Value::Null)),
                        Some(binding.policy_version.clone()),
                        binding.contract_digest.clone(),
                        Some(state),
                    );
                    crate::kernel::decision_trace::append_trace(
                        state.as_ref(),
                        agent_pid,
                        crate::kernel::decision_trace::TraceAppendOpts {
                            gateway: "ask".into(),
                            action_digest: Some(decision.action_digest.clone()),
                            outcome: format!("hitl_required:{request_id}"),
                            policy_version: Some(decision.policy_version.clone()),
                            message_type: Some("llm.chat".into()),
                            ..Default::default()
                        },
                    );
                    Err(json!({
                        "error": "hitl_required",
                        "denial_reason": "autonomy_gateway_ask",
                        "action_digest": decision.action_digest,
                        "request_id": request_id,
                        "policy_version": decision.policy_version,
                        "risk_class": decision.risk_class,
                        "gateway": decision_json(&decision),
                        "approve_url": format!(
                            "/api/v1/agents/{agent_pid}/hitl/{request_id}/approve"
                        ),
                        "honesty": "TG-2 Talk Ask — suspended until digest-bound HITL",
                    }))
                }
            }
        }
    }
}

fn hitl_policy_requires_ask(state: &PlatformState, agent_pid: &str, risk_class: &str) -> bool {
    let Some(setup) = crate::kernel::agent_identity_envelope::load_setup(state, agent_pid) else {
        return false;
    };
    use connector_trust::HitlPolicyV2;
    match setup.hitl_policy {
        HitlPolicyV2::None => false,
        HitlPolicyV2::Tool => {
            risk_class == "tool"
                || risk_class == "high"
                || risk_class == "irreversible"
                || risk_class == "egress"
                || risk_class == "shell"
                || risk_class == "fabric"
                || risk_class == "write_prod"
        }
        HitlPolicyV2::Egress => {
            risk_class == "egress" || risk_class == "network" || risk_class == "high"
        }
        HitlPolicyV2::Export => risk_class == "export" || risk_class == "high",
        HitlPolicyV2::AllMaterial => true,
    }
}

/// Infer a coarse risk class from operation/tool name for gateway wiring.
pub fn infer_risk_class(operation: &str, tool_name: &str) -> &'static str {
    // Prefer tool_name; do not treat operation "tool.dispatch" as high-risk by itself.
    let t = tool_name.to_ascii_lowercase();
    let op = operation.to_ascii_lowercase();
    if t.contains("shell")
        || t.contains("bash")
        || t.contains("exec")
        || t == "run_command"
        || t.contains("bypass")
    {
        return "shell";
    }
    if t.contains("http")
        || t.contains("fetch")
        || t.contains("egress")
        || t.contains("network")
        || t.contains("web_search")
        || t.contains("browse")
    {
        return "egress";
    }
    if op.contains("a2a") || op.contains("fabric") || t.contains("dispatch") || t.contains("signal")
    {
        return "fabric";
    }
    if t.contains("export") || t.contains("forensic") {
        return "export";
    }
    if t.contains("write")
        || t.contains("delete")
        || t.contains("purge")
        || t == "write_file"
        || t == "edit"
        || t == "multi_edit"
    {
        return "write_prod";
    }
    "tool"
}

pub fn decision_json(d: &AutonomyDecision) -> Value {
    json!({
        "schema": d.schema,
        "verdict": d.verdict,
        "reason_code": d.reason_code,
        "action_digest": d.action_digest,
        "policy_version": d.policy_version,
        "risk_class": d.risk_class,
    })
}

// ── CONP / CP/1.0 machine command admission (NP-1 / NP-2) ─────────────────

use connector_protocol::{MessageType, ProtocolCapabilityRegistry, RiskLevel};

/// Map CP RiskLevel → gateway risk_class string.
pub fn risk_class_from_cp(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Low => "normal",
        RiskLevel::Medium => "tool",
        RiskLevel::High => "high",
        RiskLevel::Critical => "irreversible",
    }
}

pub fn is_estop_capability(capability_id: &str) -> bool {
    capability_id == "safety.emergency_stop"
        || capability_id.eq_ignore_ascii_case("EmergencyStop")
}

/// NP-6 — high-risk machine motion prefers a dedicated microVM / cell, not host HAL.
pub fn prefers_microvm_hal(capability_id: &str) -> bool {
    matches!(capability_id, "machine.program_run" | "machine.rapid")
}

fn is_cross_machine_entity(entity_id: &str) -> bool {
    let t = entity_id.trim().to_ascii_lowercase();
    t.starts_with("machine:")
        || t.starts_with("device:")
        || t.starts_with("robot:")
        || t.starts_with("conp:machine")
        || t.starts_with("conp:device")
}

pub fn binding_for_conp_command(
    state: &PlatformState,
    agent_pid: &str,
    capability_id: &str,
    entity_id: &str,
    parameters: &Value,
    message_type: MessageType,
) -> ActionBinding {
    let contract = agent_principal::load_contract(state, agent_pid);
    let contract_digest = contract
        .as_ref()
        .map(|c| c.contract_digest_sha256.clone());
    let policy_version = contract
        .as_ref()
        .map(|c| c.contract_version.to_string())
        .unwrap_or_else(|| "none".into());
    let principal_id = agent_principal::load_principal(state, agent_pid).map(|p| p.principal_id);
    let params = json!({
        "schema": "connector.conp.action.v1",
        "message_type": format!("{:?}", message_type),
        "capability_id": capability_id,
        "entity_id": entity_id,
        "parameters": parameters,
    });
    ActionBinding::new(
        agent_pid.to_string(),
        format!("conp.{}", format!("{:?}", message_type).to_ascii_lowercase()),
        capability_id.to_string(),
        entity_id.to_string(),
        params,
        contract_digest,
        policy_version,
        principal_id,
    )
}

/// Admit a CONP Command (or EmergencyStop). E-stop is ambient Allow + still recorded.
pub fn admit_conp_or_ask(
    state: &SharedState,
    agent_pid: &str,
    capability_id: &str,
    entity_id: &str,
    parameters: &Value,
    message_type: MessageType,
) -> Result<AutonomyDecision, Value> {
    let reg = ProtocolCapabilityRegistry::with_defaults();
    let cap = reg.get(capability_id);
    let risk = cap
        .map(|c| risk_class_from_cp(c.risk))
        .unwrap_or_else(|| infer_risk_class("conp.command", capability_id));

    let binding = binding_for_conp_command(
        state.as_ref(),
        agent_pid,
        capability_id,
        entity_id,
        parameters,
        message_type,
    );

    if message_type.is_mutating()
        && matches!(message_type, MessageType::Command | MessageType::ClearStop)
        && is_cross_machine_entity(entity_id)
    {
        if let Err(e) = crate::substrate::effect_exclusivity::assert_conp_cross_machine_grant(
            state.as_ref(),
            agent_pid,
            entity_id,
        ) {
            record_gateway_verdict(AutonomyVerdict::Block);
            return Err(e);
        }
    }

    // Ambient e-stop: never Block / Ask-delay (CP design) — still digest-audited.
    if matches!(message_type, MessageType::EmergencyStop) || is_estop_capability(capability_id) {
        let digest = binding.digest_hex();
        let decision = AutonomyDecision {
            schema: AUTONOMY_GATEWAY_SCHEMA.into(),
            verdict: AutonomyVerdict::Allow,
            reason_code: "estop_ambient_allow".into(),
            action_digest: digest.clone(),
            policy_version: binding.policy_version.clone(),
            risk_class: "estop".into(),
        };
        record_gateway_verdict(AutonomyVerdict::Allow);
        crate::kernel::decision_trace::append_trace(
            state.as_ref(),
            agent_pid,
            crate::kernel::decision_trace::TraceAppendOpts {
                gateway: "allow".into(),
                action_digest: Some(digest),
                outcome: "estop_ambient".into(),
                policy_version: Some(binding.policy_version.clone()),
                message_type: Some("EmergencyStop".into()),
                capability_id: Some(capability_id.into()),
                ..Default::default()
            },
        );
        return Ok(decision);
    }

    // Enhance existing CONP gate: declared bound skills restrict machine capabilities.
    if let Err(e) = crate::kernel::intelligence_spec::assert_bound_skill_allows(
        state.as_ref(),
        agent_pid,
        "conp",
        capability_id,
    ) {
        record_gateway_verdict(AutonomyVerdict::Block);
        return Err(json!({
            "error": "bound_skill_denied",
            "denial_reason": e,
            "capability_id": capability_id,
            "entity_id": entity_id,
            "honesty": "Declared bound_skills restrict CONP commands",
        }));
    }
    let world = match crate::kernel::admission_layers::admit_world(
        state.as_ref(),
        agent_pid,
        entity_id,
        capability_id,
    ) {
        Ok(w) => w,
        Err(e) => {
            record_gateway_verdict(AutonomyVerdict::Block);
            return Err(json!({
                "error": "world_grant_denied",
                "denial_reason": e,
                "capability_id": capability_id,
                "entity_id": entity_id,
                "honesty": "No bypass: Cone/root require HITL; App Allow only with owner justification + root passcode; missing grant is Block",
            }));
        }
    };

    if cap.is_none() {
        let decision = AutonomyDecision {
            schema: AUTONOMY_GATEWAY_SCHEMA.into(),
            verdict: AutonomyVerdict::Block,
            reason_code: "unknown_conp_capability".into(),
            action_digest: binding.digest_hex(),
            policy_version: binding.policy_version.clone(),
            risk_class: risk.into(),
        };
        record_gateway_verdict(AutonomyVerdict::Block);
        return Err(json!({
            "error": "autonomy_gateway_block",
            "denial_reason": "unknown_conp_capability",
            "capability_id": capability_id,
            "gateway": decision_json(&decision),
            "honesty": "NP-2 — capability must exist in CP/1.0 120-cap registry",
        }));
    }

    let mut decision = autonomy_decide(state.as_ref(), &binding, risk);
    decision = fold_admission_layer(decision, &world);
    record_gateway_verdict(decision.verdict);

    match decision.verdict {
        AutonomyVerdict::Allow => {
            crate::kernel::decision_trace::append_trace(
                state.as_ref(),
                agent_pid,
                crate::kernel::decision_trace::TraceAppendOpts {
                    gateway: "allow".into(),
                    action_digest: Some(decision.action_digest.clone()),
                    outcome: format!("conp:{capability_id}"),
                    policy_version: Some(decision.policy_version.clone()),
                    message_type: Some(format!("{:?}", message_type)),
                    capability_id: Some(capability_id.into()),
                    ..Default::default()
                },
            );
            Ok(decision)
        }
        AutonomyVerdict::Block => {
            crate::kernel::decision_trace::append_trace(
                state.as_ref(),
                agent_pid,
                crate::kernel::decision_trace::TraceAppendOpts {
                    gateway: "block".into(),
                    action_digest: Some(decision.action_digest.clone()),
                    outcome: format!("blocked:{}", decision.reason_code),
                    policy_version: Some(decision.policy_version.clone()),
                    message_type: Some(format!("{:?}", message_type)),
                    capability_id: Some(capability_id.into()),
                    ..Default::default()
                },
            );
            Err(json!({
            "error": "autonomy_gateway_block",
            "denial_reason": decision.reason_code,
            "action_digest": decision.action_digest,
            "capability_id": capability_id,
            "gateway": decision_json(&decision),
            "honesty": "NP-2 Block — CONP command denied by charter/policy",
        }))
        }
        AutonomyVerdict::Ask => {
            match crate::services::agents::hitl_consume_for_action(
                Some(state),
                agent_pid,
                &decision.action_digest,
                Some(binding.policy_version.as_str()),
                binding.contract_digest.as_deref(),
            ) {
                Ok(resolution) => {
                    crate::kernel::decision_trace::append_trace(
                        state.as_ref(),
                        agent_pid,
                        crate::kernel::decision_trace::TraceAppendOpts {
                            gateway: "allow".into(),
                            action_digest: Some(decision.action_digest.clone()),
                            approval_resolution_id: resolution.resolution_id.clone(),
                            outcome: format!("conp_after_hitl:{capability_id}"),
                            policy_version: Some(decision.policy_version.clone()),
                            message_type: Some(format!("{:?}", message_type)),
                            capability_id: Some(capability_id.into()),
                            ..Default::default()
                        },
                    );
                    Ok(decision)
                }
                Err(_) => {
                    let description = format!(
                        "Approve CONP {} on {} (digest {})",
                        capability_id,
                        entity_id,
                        &decision.action_digest[..decision.action_digest.len().min(16)]
                    );
                    let request_id = crate::services::agents::hitl_submit_bound(
                        agent_pid,
                        &binding.operation,
                        &description,
                        &decision.action_digest,
                        Some(serde_json::to_value(&binding).unwrap_or(Value::Null)),
                        Some(binding.policy_version.clone()),
                        binding.contract_digest.clone(),
                        Some(state),
                    );
                    crate::kernel::decision_trace::append_trace(
                        state.as_ref(),
                        agent_pid,
                        crate::kernel::decision_trace::TraceAppendOpts {
                            gateway: "ask".into(),
                            action_digest: Some(decision.action_digest.clone()),
                            outcome: format!("hitl_required:{request_id}"),
                            policy_version: Some(decision.policy_version.clone()),
                            message_type: Some(format!("{:?}", message_type)),
                            capability_id: Some(capability_id.into()),
                            ..Default::default()
                        },
                    );
                    Err(json!({
                        "error": "hitl_required",
                        "denial_reason": "autonomy_gateway_ask",
                        "action_digest": decision.action_digest,
                        "request_id": request_id,
                        "capability_id": capability_id,
                        "gateway": decision_json(&decision),
                        "approve_url": format!(
                            "/api/v1/agents/{agent_pid}/hitl/{request_id}/approve"
                        ),
                        "honesty": "NP-2 Ask — digest-bound HITL before machine command",
                    }))
                }
            }
        }
    }
}

/// DG-09: DevGuard exec require_approval → digest-bound HITL (same consume-once as tools).
pub fn admit_devguard_exec_or_ask(
    state: &SharedState,
    agent_pid: &str,
    command: &str,
) -> Result<(), Value> {
    let result = crate::services::devguard::guard_command(state, agent_pid, command);
    if result.allowed {
        return Ok(());
    }
    if !result.requires_approval {
        return Err(json!({
            "error": "devguard_exec_denied",
            "denial_reason": result.reason,
            "verdict": result.verdict,
            "command": command,
            "dangerous": result.dangerous,
            "devguard": true,
        }));
    }

    let policy_version = crate::services::policy_config::get_active_policy(state, agent_pid)
        .map(|(_, role)| role)
        .unwrap_or_else(|| "unknown".into());
    let binding = ActionBinding::new(
        agent_pid,
        "devguard.exec",
        "shell",
        "host",
        json!({ "command": command }),
        None,
        &policy_version,
        None,
    );
    let digest = binding.digest_hex();

    match crate::services::agents::hitl_consume_for_action(
        Some(state),
        agent_pid,
        &digest,
        Some(binding.policy_version.as_str()),
        None,
    ) {
        Ok(resolution) => {
            crate::kernel::decision_trace::append_trace(
                state.as_ref(),
                agent_pid,
                crate::kernel::decision_trace::TraceAppendOpts {
                    gateway: "allow".into(),
                    action_digest: Some(digest.clone()),
                    approval_resolution_id: resolution.resolution_id.clone(),
                    outcome: "devguard_exec_after_hitl".into(),
                    policy_version: Some(binding.policy_version.clone()),
                    ..Default::default()
                },
            );
            Ok(())
        }
        Err(_) => {
            let owners = if result.approval_from.is_empty() {
                vec!["owner".to_string()]
            } else {
                result.approval_from.clone()
            };
            let description = format!(
                "DevGuard exec needs approval from [{}]: {}",
                owners.join(","),
                &command[..command.len().min(120)]
            );
            let request_id = crate::services::agents::hitl_submit_bound(
                agent_pid,
                "devguard.exec",
                &description,
                &digest,
                Some(serde_json::to_value(&binding).unwrap_or(Value::Null)),
                Some(binding.policy_version.clone()),
                None,
                Some(state),
            );
            crate::kernel::decision_trace::append_trace(
                state.as_ref(),
                agent_pid,
                crate::kernel::decision_trace::TraceAppendOpts {
                    gateway: "ask".into(),
                    action_digest: Some(digest.clone()),
                    outcome: format!("devguard_hitl_required:{request_id}"),
                    policy_version: Some(binding.policy_version.clone()),
                    ..Default::default()
                },
            );
            Err(json!({
                "error": "hitl_required",
                "denial_reason": "devguard_needs_approval",
                "verdict": "NEEDS_APPROVAL",
                "action_digest": digest,
                "request_id": request_id,
                "command": command,
                "approval_from": owners,
                "approve_url": format!("/api/v1/agents/{agent_pid}/hitl/{request_id}/approve"),
                "deny_url": format!("/api/v1/agents/{agent_pid}/hitl/{request_id}/deny"),
                "policy_bundle_id": binding.policy_version.clone(),
                "rule_id": "devguard.exec.needs_approval",
                "devguard": true,
                "honesty": "DG-09 — suspended until digest-bound HITL approve + one-shot consume on retry",
            }))
        }
    }
}

/// DG-09: DevGuard filesystem require_approval → digest-bound HITL.
pub fn admit_devguard_fs_or_ask(
    state: &SharedState,
    agent_pid: &str,
    operation: &str,
    path: &str,
) -> Result<(), Value> {
    let check = crate::services::devguard::guard_file_op(state, agent_pid, operation, path);
    if check.allowed {
        return Ok(());
    }
    if !check.requires_approval {
        return Err(json!({
            "error": "devguard_fs_denied",
            "denial_reason": check.reason,
            "verdict": check.verdict,
            "operation": operation,
            "path": path,
            "devguard": true,
        }));
    }

    let policy_version = crate::services::policy_config::get_active_policy(state, agent_pid)
        .map(|(_, role)| role)
        .unwrap_or_else(|| "unknown".into());
    let binding = ActionBinding::new(
        agent_pid,
        "devguard.fs",
        operation,
        path,
        json!({ "operation": operation, "path": path }),
        None,
        &policy_version,
        None,
    );
    let digest = binding.digest_hex();

    match crate::services::agents::hitl_consume_for_action(
        Some(state),
        agent_pid,
        &digest,
        Some(binding.policy_version.as_str()),
        None,
    ) {
        Ok(resolution) => {
            crate::kernel::decision_trace::append_trace(
                state.as_ref(),
                agent_pid,
                crate::kernel::decision_trace::TraceAppendOpts {
                    gateway: "allow".into(),
                    action_digest: Some(digest.clone()),
                    approval_resolution_id: resolution.resolution_id.clone(),
                    outcome: format!("devguard_fs_after_hitl:{operation}"),
                    policy_version: Some(binding.policy_version.clone()),
                    ..Default::default()
                },
            );
            Ok(())
        }
        Err(_) => {
            let owners = if check.approval_from.is_empty() {
                vec!["owner".to_string()]
            } else {
                check.approval_from.clone()
            };
            let description = format!(
                "DevGuard {operation} needs approval from [{}]: {path}",
                owners.join(",")
            );
            let request_id = crate::services::agents::hitl_submit_bound(
                agent_pid,
                "devguard.fs",
                &description,
                &digest,
                Some(serde_json::to_value(&binding).unwrap_or(Value::Null)),
                Some(binding.policy_version.clone()),
                None,
                Some(state),
            );
            Err(json!({
                "error": "hitl_required",
                "denial_reason": "devguard_needs_approval",
                "verdict": "NEEDS_APPROVAL",
                "action_digest": digest,
                "request_id": request_id,
                "operation": operation,
                "path": path,
                "approval_from": owners,
                "approve_url": format!("/api/v1/agents/{agent_pid}/hitl/{request_id}/approve"),
                "deny_url": format!("/api/v1/agents/{agent_pid}/hitl/{request_id}/deny"),
                "policy_bundle_id": binding.policy_version.clone(),
                "rule_id": "devguard.fs.needs_approval",
                "devguard": true,
                "honesty": "DG-09 — suspended until digest-bound HITL approve + one-shot consume on retry",
            }))
        }
    }
}

/// Binding for CNP L2 send (protocol driver).
pub fn binding_for_cnp_send(
    state: &PlatformState,
    agent_pid: &str,
    dest_cell: &str,
    payload: &Value,
) -> ActionBinding {
    let contract = agent_principal::load_contract(state, agent_pid);
    let contract_digest = contract
        .as_ref()
        .map(|c| c.contract_digest_sha256.clone());
    let policy_version = contract
        .as_ref()
        .map(|c| c.contract_version.to_string())
        .unwrap_or_else(|| "none".into());
    let principal_id = agent_principal::load_principal(state, agent_pid).map(|p| p.principal_id);
    ActionBinding::new(
        agent_pid.to_string(),
        "cnp.send",
        "cnp.send".to_string(),
        dest_cell.to_string(),
        payload.clone(),
        contract_digest,
        policy_version,
        principal_id,
    )
}

/// Admit CNP send via tool membrane (world grant + HITL) — protocol driver path.
pub fn admit_cnp_send_or_ask(
    state: &SharedState,
    agent_pid: &str,
    dest_cell: &str,
    payload: &Value,
) -> Result<AutonomyDecision, Value> {
    admit_tool_or_ask(state, agent_pid, "cnp", "cnp.send", payload)?;
    let binding = binding_for_cnp_send(state.as_ref(), agent_pid, dest_cell, payload);
    Ok(AutonomyDecision {
        schema: AUTONOMY_GATEWAY_SCHEMA.into(),
        verdict: AutonomyVerdict::Allow,
        reason_code: "cnp_send_admitted".into(),
        action_digest: binding.digest_hex(),
        policy_version: binding.policy_version.clone(),
        risk_class: infer_risk_class("cnp.send", "cnp.send").into(),
    })
}

/// Binding for CNP actuation (protocol driver). Distinct from cognitive send.
pub fn binding_for_cnp_actuation(
    state: &PlatformState,
    agent_pid: &str,
    to_agent: &str,
    payload: &Value,
) -> ActionBinding {
    let contract = agent_principal::load_contract(state, agent_pid);
    let contract_digest = contract
        .as_ref()
        .map(|c| c.contract_digest_sha256.clone());
    let policy_version = contract
        .as_ref()
        .map(|c| c.contract_version.to_string())
        .unwrap_or_else(|| "none".into());
    let principal_id = agent_principal::load_principal(state, agent_pid).map(|p| p.principal_id);
    ActionBinding::new(
        agent_pid.to_string(),
        "cnp.actuation",
        "cnp.actuation".to_string(),
        to_agent.to_string(),
        payload.clone(),
        contract_digest,
        policy_version,
        principal_id,
    )
}

/// Admit CNP actuation via tool membrane — not SIL-certified motion.
pub fn admit_cnp_actuation_or_ask(
    state: &SharedState,
    agent_pid: &str,
    to_agent: &str,
    payload: &Value,
) -> Result<AutonomyDecision, Value> {
    admit_tool_or_ask(state, agent_pid, "cnp", "cnp.actuation", payload)?;
    let binding = binding_for_cnp_actuation(state.as_ref(), agent_pid, to_agent, payload);
    Ok(AutonomyDecision {
        schema: AUTONOMY_GATEWAY_SCHEMA.into(),
        verdict: AutonomyVerdict::Allow,
        reason_code: "cnp_actuation_admitted".into(),
        action_digest: binding.digest_hex(),
        policy_version: binding.policy_version.clone(),
        risk_class: infer_risk_class("cnp.actuation", "cnp.actuation").into(),
    })
}

/// Binding for A2A task send (protocol driver).
pub fn binding_for_a2a_send(
    state: &PlatformState,
    agent_pid: &str,
    peer_or_session: &str,
    parameters: &Value,
) -> ActionBinding {
    let contract = agent_principal::load_contract(state, agent_pid);
    let contract_digest = contract
        .as_ref()
        .map(|c| c.contract_digest_sha256.clone());
    let policy_version = contract
        .as_ref()
        .map(|c| c.contract_version.to_string())
        .unwrap_or_else(|| "none".into());
    let principal_id = agent_principal::load_principal(state, agent_pid).map(|p| p.principal_id);
    ActionBinding::new(
        agent_pid.to_string(),
        "a2a.send",
        "a2a.send".to_string(),
        peer_or_session.to_string(),
        parameters.clone(),
        contract_digest,
        policy_version,
        principal_id,
    )
}

/// Admit A2A send via tool membrane — cards authenticate peers; Connector authorizes.
pub fn admit_a2a_or_ask(
    state: &SharedState,
    agent_pid: &str,
    peer_or_session: &str,
    parameters: &Value,
) -> Result<AutonomyDecision, Value> {
    if let Err(e) = crate::kernel::intelligence_spec::assert_bound_skill_allows(
        state.as_ref(),
        agent_pid,
        "a2a",
        "a2a.send",
    ) {
        record_gateway_verdict(AutonomyVerdict::Block);
        return Err(json!({
            "error": "bound_skill_denied",
            "denial_reason": e,
            "honesty": "Declared bound_skills restrict A2A sends",
        }));
    }
    admit_tool_or_ask(state, agent_pid, "a2a", "a2a.send", parameters)?;
    let binding = binding_for_a2a_send(state.as_ref(), agent_pid, peer_or_session, parameters);
    Ok(AutonomyDecision {
        schema: AUTONOMY_GATEWAY_SCHEMA.into(),
        verdict: AutonomyVerdict::Allow,
        reason_code: "a2a_send_admitted".into(),
        action_digest: binding.digest_hex(),
        policy_version: binding.policy_version.clone(),
        risk_class: infer_risk_class("a2a.send", "a2a.send").into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn talk_binding_digest_content_sensitive() {
        let a = ActionBinding::new(
            "agent_1",
            "llm.chat",
            "talk",
            "ns/a",
            json!({"namespace": "ns/a", "content_sha256": "aaa"}),
            Some("cd".into()),
            "1",
            Some("cnktr:agent:agent_1".into()),
        );
        let mut b = a.clone();
        assert_eq!(a.digest_hex(), b.digest_hex());
        b.parameters = json!({"namespace": "ns/a", "content_sha256": "bbb"});
        assert_ne!(a.digest_hex(), b.digest_hex());
    }

    #[test]
    fn digest_stable_and_param_sensitive() {
        let a = ActionBinding::new(
            "agent_1",
            "tool.invoke",
            "sql_execute",
            "prod-db",
            json!({"statement": "UPDATE t SET x=1"}),
            Some("cdigest".into()),
            "2026.08.12",
            Some("cnktr:agent:agent_1".into()),
        );
        let mut b = a.clone();
        assert_eq!(a.digest_hex(), b.digest_hex());
        b.parameters = json!({"statement": "UPDATE t SET x=2"});
        assert_ne!(a.digest_hex(), b.digest_hex());
    }

    #[test]
    fn canonical_sorts_keys() {
        let v = json!({"b": 1, "a": {"z": 2, "y": 3}});
        let c = canonical_json(&v);
        assert_eq!(
            serde_json::to_string(&c).unwrap(),
            r#"{"a":{"y":3,"z":2},"b":1}"#
        );
    }

    #[test]
    fn conp_move_axis_digest_param_sensitive() {
        let a = ActionBinding::new(
            "agent_m",
            "conp.command",
            "machine.move_axis",
            "conp:machine:m1",
            json!({"schema":"connector.conp.action.v1","parameters":{"axis":"X","target_mm":1.0}}),
            Some("cd".into()),
            "1",
            None,
        );
        let mut b = a.clone();
        assert_eq!(a.digest_hex(), b.digest_hex());
        b.parameters = json!({"schema":"connector.conp.action.v1","parameters":{"axis":"X","target_mm":2.0}});
        assert_ne!(a.digest_hex(), b.digest_hex());
    }

    #[test]
    fn cp_risk_mapping() {
        assert_eq!(risk_class_from_cp(RiskLevel::Critical), "irreversible");
        assert_eq!(risk_class_from_cp(RiskLevel::High), "high");
        assert!(is_estop_capability("safety.emergency_stop"));
        assert!(prefers_microvm_hal("machine.program_run"));
        assert!(prefers_microvm_hal("machine.rapid"));
        assert!(!prefers_microvm_hal("machine.move_axis"));
        assert!(is_cross_machine_entity("machine:arm-1"));
        assert!(!is_cross_machine_entity("agent_1"));
    }

    #[test]
    fn fold_app_cannot_downgrade_ask_or_block() {
        use crate::kernel::admission_layers::{AdmissionLayer, WorldAdmit};
        let allow = AutonomyDecision {
            schema: AUTONOMY_GATEWAY_SCHEMA.into(),
            verdict: AutonomyVerdict::Allow,
            reason_code: "charter_allow".into(),
            action_digest: "d".into(),
            policy_version: "1".into(),
            risk_class: "tool".into(),
        };
        let mut ask = allow.clone();
        ask.verdict = AutonomyVerdict::Ask;
        let mut block = allow.clone();
        block.verdict = AutonomyVerdict::Block;
        assert_eq!(
            fold_admission_layer(allow.clone(), &WorldAdmit::Layer(AdmissionLayer::Cone)).verdict,
            AutonomyVerdict::Ask
        );
        assert_eq!(
            fold_admission_layer(allow.clone(), &WorldAdmit::Layer(AdmissionLayer::App)).verdict,
            AutonomyVerdict::Allow
        );
        assert_eq!(
            fold_admission_layer(ask, &WorldAdmit::Layer(AdmissionLayer::App)).verdict,
            AutonomyVerdict::Ask
        );
        assert_eq!(
            fold_admission_layer(block, &WorldAdmit::Layer(AdmissionLayer::App)).verdict,
            AutonomyVerdict::Block
        );
    }
}
