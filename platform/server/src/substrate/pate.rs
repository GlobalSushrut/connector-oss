//! Probabilistic Augmented Task Engine (PATE) — durable admit/commit envelope.
//!
//! Wraps existing [`ActionBinding`] admission. Does **not** replace
//! `admit_tool_or_ask` / `admit_talk_or_ask` / `admit_conp_or_ask` — it stamps
//! an Augmented Task Unit (ATU) with broker epoch, IAC epoch, footprint, and
//! optional mission_journal linkage for resume / no-duplicate effects.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{ConnectorError, DenialReason};
use crate::kernel::action_binding::{
    self, ActionBinding, AutonomyDecision, AutonomyVerdict,
};
use crate::kernel::mission_journal::{self, StepKind};
use crate::state::SharedState;

pub const PATE_SCHEMA: &str = "connector.pate.atu.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectKind {
    LlmChat,
    ToolDispatch,
    ConpCommand,
    CnpSend,
    MemoryWrite,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskVerdict {
    Proceed,
    AskHitl,
    DeferRedo,
    Quarantine,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolFootprint {
    pub read_refs: Vec<String>,
    pub write_refs: Vec<String>,
    pub idempotent: bool,
    pub inverse_registered: bool,
    pub requires_hitl: bool,
    pub reversibility: String,
    pub conp_capability: Option<String>,
    pub risk_class: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AugmentedTaskUnit {
    pub schema: String,
    pub task_id: String,
    pub agent_pid: String,
    pub broker_epoch: u64,
    pub iac_epoch: u64,
    pub consistency_level: u8,
    pub effect_kind: EffectKind,
    pub action_digest: String,
    pub tool_footprint: ToolFootprint,
    pub mission_id: Option<String>,
    pub mission_step_id: Option<String>,
    pub verdict: TaskVerdict,
    pub autonomy: Option<AutonomyDecision>,
    pub minted_at_ms: i64,
    /// Committed context reference when agent memory plane is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_ref: Option<connector_trust::ContextReference>,
    /// Correlation for this task. Empty on older records. Never admits.
    #[serde(default)]
    pub spine: TaskSpine,
}

/// Refs joined to one `task_id`. Absent fields stay absent.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct TaskSpine {
    #[serde(default)]
    pub operator_sub: Option<String>,
    #[serde(default)]
    pub workload_id: Option<String>,
    #[serde(default)]
    pub generation_id: Option<String>,
    #[serde(default)]
    pub contract_digest: Option<String>,
    #[serde(default)]
    pub grant_revision: Option<String>,
    #[serde(default)]
    pub effect_archetype: Option<String>,
    #[serde(default)]
    pub idempotency_key: Option<String>,
    #[serde(default)]
    pub execution_attempts: u32,
    /// `reserved`, `committed`, `released`, or `absent`.
    #[serde(default)]
    pub spend: String,
    #[serde(default)]
    pub hitl_request_id: Option<String>,
    #[serde(default)]
    pub runtime_handle: Option<String>,
    #[serde(default)]
    pub artifact_digest: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub observed: bool,
    #[serde(default)]
    pub trace_id: Option<String>,
    #[serde(default)]
    pub receipt_id: Option<String>,
    #[serde(default)]
    pub moment_id: Option<String>,
    #[serde(default)]
    pub awd_key: Option<String>,
    #[serde(default)]
    pub aapi_ref: Option<String>,
    /// This record does not mint Allow.
    #[serde(default)]
    pub admits: bool,
}

#[derive(Debug, Clone)]
pub struct TaskAttempt {
    pub idempotency_key: String,
    pub mutating: bool,
    pub observed: bool,
}

#[derive(Debug, Clone, Default)]
pub struct TaskRefs {
    pub operator_sub: Option<String>,
    pub workload_id: Option<String>,
    pub generation_id: Option<String>,
    pub contract_digest: Option<String>,
    pub grant_revision: Option<String>,
    pub effect_archetype: Option<String>,
    pub hitl_request_id: Option<String>,
    pub runtime_handle: Option<String>,
    pub artifact_digest: Option<String>,
    pub trace_id: Option<String>,
    pub receipt_id: Option<String>,
    pub moment_id: Option<String>,
    pub awd_key: Option<String>,
    pub aapi_ref: Option<String>,
}

pub fn commits_spend(verdict: TaskVerdict, observed: bool) -> bool {
    observed && verdict == TaskVerdict::Proceed
}

/// Only a proceed verdict may execute. Ask, defer, quarantine, and block do not.
pub fn host_admission_allows_execution(verdict: TaskVerdict) -> bool {
    verdict == TaskVerdict::Proceed
}

/// Close one task record. Does not admit, does not call a backend, and forces `admits` false.
pub fn finish_task_record(
    mut atu: AugmentedTaskUnit,
    attempt: &TaskAttempt,
    refs: TaskRefs,
) -> Result<AugmentedTaskUnit, &'static str> {
    if attempt.mutating && attempt.idempotency_key.trim().is_empty() {
        return Err("idempotency_required");
    }
    if attempt.mutating && atu.spine.execution_attempts >= 1 {
        return Err("one_execution_attempt");
    }
    let commit = commits_spend(atu.verdict, attempt.observed);
    atu.spine.operator_sub = refs.operator_sub.or(atu.spine.operator_sub);
    atu.spine.workload_id = refs.workload_id.or(atu.spine.workload_id);
    atu.spine.generation_id = refs.generation_id.or(atu.spine.generation_id);
    atu.spine.contract_digest = refs.contract_digest.or(atu.spine.contract_digest);
    atu.spine.grant_revision = refs.grant_revision.or(atu.spine.grant_revision);
    atu.spine.effect_archetype = refs.effect_archetype.or(atu.spine.effect_archetype);
    atu.spine.hitl_request_id = refs.hitl_request_id.or(atu.spine.hitl_request_id);
    atu.spine.runtime_handle = refs.runtime_handle.or(atu.spine.runtime_handle);
    atu.spine.artifact_digest = refs.artifact_digest.or(atu.spine.artifact_digest);
    atu.spine.trace_id = refs.trace_id.or(atu.spine.trace_id);
    atu.spine.moment_id = refs.moment_id.or(atu.spine.moment_id);
    atu.spine.awd_key = refs.awd_key.or(atu.spine.awd_key);
    atu.spine.aapi_ref = refs.aapi_ref.or(atu.spine.aapi_ref);
    atu.spine.admits = false;
    if commit {
        atu.spine.execution_attempts = atu.spine.execution_attempts.saturating_add(1);
        atu.spine.idempotency_key = Some(attempt.idempotency_key.clone());
        atu.spine.spend = "committed".into();
        atu.spine.outcome = Some("committed".into());
        atu.spine.observed = true;
        atu.spine.receipt_id = refs.receipt_id.or(atu.spine.receipt_id);
    } else {
        atu.spine.spend = "released".into();
        atu.spine.outcome = Some("released".into());
        atu.spine.observed = false;
        atu.spine.receipt_id = None;
    }
    Ok(atu)
}

impl AugmentedTaskUnit {
    pub fn to_json(&self) -> Value {
        serde_json::to_value(self).unwrap_or(Value::Null)
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn consistency_level_from_env() -> u8 {
    std::env::var("CONNECTOR_CONSISTENCY_LEVEL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            if crate::services::playground::is_playground_mode() {
                1
            } else {
                2
            }
        })
}

fn mint_task_id(agent_pid: &str, digest: &str, epoch: u64) -> String {
    let raw = format!("{agent_pid}|{digest}|{epoch}|{}", now_ms());
    let h = format!("{:x}", Sha256::digest(raw.as_bytes()));
    format!("pate_{epoch}_{}", &h[..12])
}

fn footprint_for(
    effect: EffectKind,
    binding: &ActionBinding,
    risk_class: &str,
    requires_hitl: bool,
) -> ToolFootprint {
    let mut footprint = ToolFootprint {
        read_refs: vec![format!("agent:{}", binding.agent_pid)],
        write_refs: match effect {
            EffectKind::LlmChat => vec![],
            _ => vec![format!(
                "{}:{}",
                binding.operation, binding.target.resource
            )],
        },
        idempotent: matches!(effect, EffectKind::LlmChat),
        inverse_registered: false,
        requires_hitl,
        reversibility: String::new(),
        conp_capability: if binding.operation.starts_with("conp") {
            Some(binding.target.tool_name.clone())
        } else {
            None
        },
        risk_class: risk_class.into(),
    };
    let class = crate::substrate::rgo::classify_action(binding, &footprint);
    footprint.reversibility = class.as_str().into();
    // RGO may raise HITL requirement for R2+/tier without replacing ActionBinding Ask.
    if !requires_hitl {
        let mode = crate::substrate::rgo::resolve_oversight(
            class,
            crate::substrate::rgo::autonomy_tier(),
            false,
        );
        if matches!(
            mode,
            crate::substrate::rgo::OversightMode::HitlDigest
                | crate::substrate::rgo::OversightMode::Halt
        ) {
            footprint.requires_hitl = true;
        }
    }
    footprint
}

fn map_verdict(decision: &AutonomyDecision) -> TaskVerdict {
    match decision.verdict {
        AutonomyVerdict::Allow => TaskVerdict::Proceed,
        AutonomyVerdict::Ask => TaskVerdict::AskHitl,
        AutonomyVerdict::Block => TaskVerdict::Block,
    }
}

fn value_err_to_connector(v: Value) -> ConnectorError {
    let msg = v
        .get("error")
        .or_else(|| v.get("message"))
        .and_then(|x| x.as_str())
        .unwrap_or("pate_admit_denied");
    ConnectorError::new(DenialReason::PolicyDenied, msg.to_string())
        .with_denied_resource("pate.admit")
}

/// Mint an ATU after a successful AutonomyGateway decision.
pub fn mint_atu(
    state: &SharedState,
    binding: &ActionBinding,
    decision: &AutonomyDecision,
    effect_kind: EffectKind,
    mission_id: Option<String>,
    mission_step_id: Option<String>,
) -> AugmentedTaskUnit {
    let cell = state.cells.get_or_create(&binding.agent_pid);
    let iac_epoch = cell.current_epoch();
    let broker_epoch =
        crate::substrate::llm_context_broker::current_generation(state, &binding.agent_pid);
    let requires_hitl = decision.verdict == AutonomyVerdict::Ask;
    let mut footprint = footprint_for(effect_kind, binding, &decision.risk_class, requires_hitl);
    let egcm_bump =
        crate::substrate::egcm::snapshot_for_agent(state.as_ref(), &binding.agent_pid).disorder_bump;
    let (oversight, nf3) =
        crate::substrate::nf3::gate_effect(binding, &footprint, egcm_bump);
    if matches!(
        oversight,
        crate::substrate::rgo::OversightMode::HitlDigest
            | crate::substrate::rgo::OversightMode::Halt
    ) {
        footprint.requires_hitl = true;
    }
    // Shadow Knot-21 observe (never authorizes).
    let _ = crate::substrate::knot21::observe(state.as_ref(), &binding.agent_pid);
    let mut verdict = map_verdict(decision);
    if !nf3.ok {
        verdict = TaskVerdict::Block;
    }
    let context_ref = if crate::substrate::agent_memory::enabled() {
        Some(crate::substrate::agent_memory::context_store::context_ref(
            state.as_ref(),
            &binding.agent_pid,
        ))
    } else {
        None
    };
    let atu = AugmentedTaskUnit {
        schema: PATE_SCHEMA.into(),
        task_id: mint_task_id(&binding.agent_pid, &decision.action_digest, iac_epoch),
        agent_pid: binding.agent_pid.clone(),
        broker_epoch,
        iac_epoch,
        consistency_level: consistency_level_from_env(),
        effect_kind,
        action_digest: decision.action_digest.clone(),
        tool_footprint: footprint,
        mission_id,
        mission_step_id,
        verdict,
        autonomy: Some(decision.clone()),
        minted_at_ms: now_ms(),
        context_ref,
        spine: TaskSpine {
            generation_id: Some(broker_epoch.to_string()),
            effect_archetype: serde_json::to_value(effect_kind)
                .ok()
                .and_then(|value| value.as_str().map(|text| text.to_string())),
            contract_digest: crate::kernel::agent_principal::load_contract(
                state.as_ref(),
                &binding.agent_pid,
            )
            .map(|contract| contract.contract_digest_sha256),
            admits: false,
            ..TaskSpine::default()
        },
    };
    persist_atu(state, &atu, None, None);
    let verdict = serde_json::to_value(&atu.verdict)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "absent".into());
    crate::substrate::awd::attach_prediction(state, &atu.task_id, &atu.agent_pid, &verdict);
    atu
}

pub const ATU_FOLDER: &str = "pate_atu_v1";
pub const MISMATCH_FOLDER: &str = "policy_mismatch_v1";

fn persist_atu(
    state: &SharedState,
    atu: &AugmentedTaskUnit,
    outcome: Option<&str>,
    moment_id: Option<&str>,
) {
    let mut body = atu.to_json();
    if let Some(obj) = body.as_object_mut() {
        if let Some(outcome) = outcome {
            obj.insert("outcome".into(), json!(outcome));
        }
        if let Some(moment_id) = moment_id {
            obj.insert("moment_id".into(), json!(moment_id));
        }
    }
    let Ok(mut es) = state.engine_store.lock() else {
        return;
    };
    let _ = es.folder_put(ATU_FOLDER, &atu.task_id, &body);
    let _ = es.folder_put(ATU_FOLDER, &format!("latest:{}", atu.agent_pid), &body);
}

/// PATE already admitted. A later runtime deny wins, and both facts stay on one record.
pub fn note_runtime_deny_after_admit(
    state: &crate::state::PlatformState,
    agent_pid: &str,
    pate_task_id: &str,
    action_digest: &str,
    controller: &str,
    denial_reason: &str,
    detail: &str,
) {
    let rec = json!({
        "schema": "connector.policy_mismatch.v1",
        "agent_pid": agent_pid,
        "pate_task_id": pate_task_id,
        "action_digest": action_digest,
        "pate_admitted": true,
        "runtime_controller": controller,
        "denial_reason": denial_reason,
        "detail": detail,
        "deny_wins": true,
        "openshell_opa": controller == "openshell",
        "issued_at_ms": now_ms(),
        "honesty": "PATE admitted the intent. This controller denied the effect. OpenShell OPA is not claimed unless runtime_controller is openshell.",
    });
    let Ok(mut es) = state.engine_store.lock() else {
        return;
    };
    let _ = es.folder_put(MISMATCH_FOLDER, &format!("deny:{pate_task_id}"), &rec);
    let _ = es.folder_put(MISMATCH_FOLDER, &format!("latest:{agent_pid}"), &rec);
}

/// L1: reject ATU if the IntelligenceCell epoch moved since mint.
pub fn assert_atu_fresh(state: &SharedState, atu: &AugmentedTaskUnit) -> Result<(), ConnectorError> {
    let cell = state.cells.get_or_create(&atu.agent_pid);
    let live = cell.current_epoch();
    if live != atu.iac_epoch {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!(
                "pate_stale_epoch: atu={} minted={} live={}",
                atu.task_id, atu.iac_epoch, live
            ),
        )
        .with_denied_resource("pate.epoch")
        .with_hint(
            "Retry Talk/tool after quarantine or identity change (409 DeferRedo semantics)",
        ));
    }
    let had_stamp = cell
        .read_set
        .read()
        .map(|r| r.stamped_epoch != 0)
        .unwrap_or(false);
    if atu.consistency_level >= 2 && had_stamp {
        if let Err(msg) = cell.assert_read_set_fresh_or_stale() {
            return Err(ConnectorError::new(DenialReason::PolicyDenied, msg)
                .with_denied_resource("pate.read_set")
                .with_hint("World-model read-set changed; replan before commit (HTTP 409)"));
        }
    }
    Ok(())
}

/// Admit Talk through existing ActionBinding, then wrap as ATU.
/// Optionally attaches / creates a mission for journal continuity.
pub fn admit_talk(
    state: &SharedState,
    agent_pid: &str,
    namespace: &str,
    content_for_digest: &str,
    mission_id: Option<String>,
) -> Result<AugmentedTaskUnit, ConnectorError> {
    action_binding::admit_talk_or_ask(state, agent_pid, namespace, content_for_digest)
        .map_err(value_err_to_connector)?;
    let content_sha256 = format!(
        "{:x}",
        Sha256::digest(content_for_digest.as_bytes())
    );
    let binding =
        action_binding::binding_for_talk(state.as_ref(), agent_pid, namespace, &content_sha256);
    let decision = action_binding::autonomy_decide(state.as_ref(), &binding, "llm");
    let mission_id = match mission_id {
        Some(m) if !m.trim().is_empty() => Some(m),
        _ => ensure_talk_mission(state, agent_pid),
    };
    let atu = mint_atu(
        state,
        &binding,
        &decision,
        EffectKind::LlmChat,
        mission_id,
        None,
    );
    if atu.verdict == TaskVerdict::Block {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!("pate_talk_block: {}", decision.reason_code),
        ));
    }
    crate::substrate::arc::governor::record_pate_admit(state, &atu)?;
    let gen = crate::substrate::llm_context_broker::current_generation(state, agent_pid).to_string();
    if let Ok(ceiling) = crate::substrate::spend_cease::ensure_ceiling(
        state.as_ref(),
        agent_pid,
        &gen,
        atu.mission_id.as_deref().unwrap_or("talk"),
    ) {
        if let Err(e) = crate::substrate::spend_cease::scope_estimate_gate(
            content_for_digest,
            ceiling.max_usd,
        ) {
            return Err(ConnectorError::new(DenialReason::PolicyDenied, e));
        }
    }
    let projected_tokens = (content_for_digest.len() as u64 / 4).saturating_add(2048);
    spend_gate_admit(state, agent_pid, &atu, "talk", Some(projected_tokens))?;
    Ok(atu)
}

/// Create a short-lived Talk mission unless CONNECTOR_TALK_MISSION=0.
fn ensure_talk_mission(state: &SharedState, agent_pid: &str) -> Option<String> {
    let enabled = match std::env::var("CONNECTOR_TALK_MISSION") {
        Ok(v) => {
            let t = v.trim();
            !(t == "0" || t.eq_ignore_ascii_case("false") || t.eq_ignore_ascii_case("off"))
        }
        Err(_) => true,
    };
    if !enabled {
        return None;
    }
    mission_journal::create_mission(
        state.as_ref(),
        agent_pid,
        Some("talk".into()),
    )
    .ok()
    .map(|m| m.mission_id)
}

/// Admit a tool effect through existing ActionBinding, then wrap as ATU.
pub fn admit_tool(
    state: &SharedState,
    agent_pid: &str,
    bridge_id: &str,
    tool_name: &str,
    arguments: &Value,
    mission_id: Option<String>,
) -> Result<AugmentedTaskUnit, ConnectorError> {
    action_binding::admit_tool_or_ask(state, agent_pid, bridge_id, tool_name, arguments)
        .map_err(value_err_to_connector)?;
    let binding =
        action_binding::binding_for_tool(state.as_ref(), agent_pid, bridge_id, tool_name, arguments);
    let risk = action_binding::infer_risk_class(&binding.operation, tool_name);
    let decision = action_binding::autonomy_decide(state.as_ref(), &binding, risk);
    let atu = mint_atu(
        state,
        &binding,
        &decision,
        EffectKind::ToolDispatch,
        mission_id,
        None,
    );
    if atu.verdict == TaskVerdict::Block {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!("pate_block: {}", decision.reason_code),
        ));
    }
    crate::substrate::arc::governor::record_pate_admit(state, &atu)?;
    spend_gate_admit(state, agent_pid, &atu, "tool", None)?;
    Ok(atu)
}

/// Shared SpendCease admit gate: live generation + ceiling + hop reserve.
/// On budget/iteration trip → kernel Cease so the model cannot keep looping.
fn spend_gate_admit(
    state: &SharedState,
    agent_pid: &str,
    atu: &AugmentedTaskUnit,
    hop_kind: &str,
    projected_tokens_override: Option<u64>,
) -> Result<(), ConnectorError> {
    let gen = crate::substrate::llm_context_broker::current_generation(state, agent_pid).to_string();
    let _ = crate::substrate::spend_cease::ensure_ceiling(
        state.as_ref(),
        agent_pid,
        &gen,
        atu.mission_id.as_deref().unwrap_or(hop_kind),
    );
    if let Err(e) = crate::substrate::spend_cease::assert_live_generation(state, agent_pid, &gen) {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!("pate_{hop_kind}_stale_generation: {e}"),
        ));
    }
    crate::substrate::spend_cease::clear_post_cease_retries(state.as_ref(), agent_pid);
    let hop_key = format!("{hop_kind}:{}", atu.task_id);
    let projected_tokens: u64 = projected_tokens_override.unwrap_or(match atu.effect_kind {
        EffectKind::LlmChat => 4096,
        EffectKind::ToolDispatch => 512,
        _ => 256,
    });
    let projected_usd = (projected_tokens as f64) * 0.000002;
    if let Err(e) = crate::substrate::spend_cease::reserve_hop(
        state.as_ref(),
        agent_pid,
        &gen,
        &hop_key,
        projected_usd,
        projected_tokens,
    ) {
        if e.contains("exhausted") || e.contains("iteration") || e.starts_with("spend_") {
            let _ = crate::substrate::spend_cease::kernel_cease(
                state,
                agent_pid,
                if e.contains("iteration") {
                    connector_trust::CeaseReason::IterationCap
                } else {
                    connector_trust::CeaseReason::BudgetExhausted
                },
            );
            return Err(ConnectorError::new(
                DenialReason::PolicyDenied,
                format!("pate_{hop_kind}_spend_cease: {e}"),
            ));
        }
    }
    Ok(())
}

/// Admit a CONP command through ActionBinding, then wrap as ATU.
pub fn admit_conp(
    state: &SharedState,
    agent_pid: &str,
    capability_id: &str,
    entity_id: &str,
    parameters: &Value,
    message_type: connector_protocol::MessageType,
    mission_id: Option<String>,
) -> Result<AugmentedTaskUnit, ConnectorError> {
    let decision = action_binding::admit_conp_or_ask(
        state,
        agent_pid,
        capability_id,
        entity_id,
        parameters,
        message_type,
    )
    .map_err(value_err_to_connector)?;
    let binding = action_binding::binding_for_conp_command(
        state.as_ref(),
        agent_pid,
        capability_id,
        entity_id,
        parameters,
        message_type,
    );
    let atu = mint_atu(
        state,
        &binding,
        &decision,
        EffectKind::ConpCommand,
        mission_id,
        None,
    );
    if atu.verdict == TaskVerdict::Block {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!("pate_conp_block: {}", decision.reason_code),
        ));
    }
    // RGO HitlDigest on irreversible CONP (e-stop stays ambient Allow via admit_conp_or_ask).
    if atu.tool_footprint.requires_hitl && decision.verdict == AutonomyVerdict::Allow {
        let class = crate::substrate::rgo::ReversibilityClass::from_label(
            &atu.tool_footprint.reversibility,
        );
        let mode = crate::substrate::rgo::resolve_oversight(
            class,
            crate::substrate::rgo::autonomy_tier(),
            crate::substrate::egcm::snapshot_for_agent(state.as_ref(), agent_pid).disorder_bump,
        );
        if matches!(mode, crate::substrate::rgo::OversightMode::HitlDigest)
            && !matches!(message_type, connector_protocol::MessageType::EmergencyStop)
        {
            return Err(ConnectorError::new(
                DenialReason::PolicyDenied,
                format!(
                    "rgo_hitl_required:{}:{}",
                    atu.tool_footprint.reversibility, decision.action_digest
                ),
            )
            .with_denied_resource("rgo.hitl")
            .with_hint("Approve digest-bound HITL then retry CONP command"));
        }
    }
    crate::substrate::arc::governor::record_pate_admit(state, &atu)?;
    Ok(atu)
}

/// Admit a CNP send through ActionBinding, then wrap as ATU (protocol driver).
pub fn admit_cnp_send(
    state: &SharedState,
    agent_pid: &str,
    dest_cell: &str,
    payload: &Value,
    mission_id: Option<String>,
) -> Result<AugmentedTaskUnit, ConnectorError> {
    let decision = action_binding::admit_cnp_send_or_ask(state, agent_pid, dest_cell, payload)
        .map_err(value_err_to_connector)?;
    let binding =
        action_binding::binding_for_cnp_send(state.as_ref(), agent_pid, dest_cell, payload);
    let atu = mint_atu(
        state,
        &binding,
        &decision,
        EffectKind::CnpSend,
        mission_id,
        None,
    );
    if atu.verdict == TaskVerdict::Block {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!("pate_cnp_block: {}", decision.reason_code),
        ));
    }
    crate::substrate::arc::governor::record_pate_admit(state, &atu)?;
    Ok(atu)
}

/// Admit a CNP actuation through ActionBinding, then wrap as ATU.
pub fn admit_cnp_actuation(
    state: &SharedState,
    agent_pid: &str,
    to_agent: &str,
    payload: &Value,
    mission_id: Option<String>,
) -> Result<AugmentedTaskUnit, ConnectorError> {
    let decision =
        action_binding::admit_cnp_actuation_or_ask(state, agent_pid, to_agent, payload)
            .map_err(value_err_to_connector)?;
    let binding =
        action_binding::binding_for_cnp_actuation(state.as_ref(), agent_pid, to_agent, payload);
    let atu = mint_atu(
        state,
        &binding,
        &decision,
        EffectKind::CnpSend,
        mission_id,
        None,
    );
    if atu.verdict == TaskVerdict::Block {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!("pate_cnp_actuation_block: {}", decision.reason_code),
        ));
    }
    crate::substrate::arc::governor::record_pate_admit(state, &atu)?;
    Ok(atu)
}

/// Admit an A2A task send through ActionBinding, then wrap as ATU (protocol driver).
pub fn admit_a2a(
    state: &SharedState,
    agent_pid: &str,
    peer_or_session: &str,
    parameters: &Value,
    mission_id: Option<String>,
) -> Result<AugmentedTaskUnit, ConnectorError> {
    let decision = action_binding::admit_a2a_or_ask(state, agent_pid, peer_or_session, parameters)
        .map_err(value_err_to_connector)?;
    let binding =
        action_binding::binding_for_a2a_send(state.as_ref(), agent_pid, peer_or_session, parameters);
    let atu = mint_atu(
        state,
        &binding,
        &decision,
        EffectKind::ToolDispatch,
        mission_id,
        None,
    );
    if atu.verdict == TaskVerdict::Block {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!("pate_a2a_block: {}", decision.reason_code),
        ));
    }
    crate::substrate::arc::governor::record_pate_admit(state, &atu)?;
    Ok(atu)
}

/// Persist ATU outcome into mission journal when a mission is attached.
pub fn complete_augmented_task(
    state: &SharedState,
    atu: &AugmentedTaskUnit,
    outcome: &str,
    detail: Value,
) -> Result<Value, ConnectorError> {
    assert_atu_fresh(state, atu)?;
    let observed = effect_observed(outcome, &detail);
    let idem = detail
        .get("idempotency_key")
        .and_then(Value::as_str)
        .filter(|key| !key.is_empty())
        .unwrap_or(atu.task_id.as_str())
        .to_string();
    let mut draft = atu.clone();
    draft.spine.execution_attempts = stored_execution_attempts(state, &atu.task_id);
    let mut finished = finish_task_record(
        draft,
        &TaskAttempt {
            idempotency_key: idem,
            mutating: !atu.tool_footprint.idempotent,
            observed,
        },
        task_refs_from_detail(&detail),
    )
    .map_err(|reason| ConnectorError::new(DenialReason::PolicyDenied, reason.to_string()))?;
    // SpendCease: commit only an observed proceed. Everything else returns the reservation.
    let gen =
        crate::substrate::llm_context_broker::current_generation(state, &atu.agent_pid).to_string();
    let hop_kind = match atu.effect_kind {
        EffectKind::LlmChat => "talk",
        EffectKind::ToolDispatch => "tool",
        _ => "effect",
    };
    let hop_key = format!("{hop_kind}:{}", atu.task_id);
    let tokens = detail
        .get("output_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
        .saturating_add(detail.get("input_tokens").and_then(|v| v.as_u64()).unwrap_or(0));
    let tokens = if tokens == 0 {
        match atu.effect_kind {
            EffectKind::ToolDispatch => 512,
            _ => 256,
        }
    } else {
        tokens
    };
    let usd = (tokens as f64) * 0.000002;
    if finished.spine.spend == "committed" {
        let _ = crate::substrate::spend_cease::commit_hop(
            state.as_ref(),
            &atu.agent_pid,
            &gen,
            &hop_key,
            usd,
            tokens,
        );
    } else {
        let _ = crate::substrate::spend_cease::release_hop(state.as_ref(), &atu.agent_pid, &hop_key);
    }
    if let Some(mid) = atu.mission_id.as_deref() {
        let kind = match atu.effect_kind {
            EffectKind::LlmChat => StepKind::Llm,
            EffectKind::ToolDispatch => StepKind::Tool,
            EffectKind::ConpCommand => StepKind::ConpCommand,
            EffectKind::CnpSend => StepKind::CnpMessage,
            _ => StepKind::Tool,
        };
        let idem = format!("pate:{}:{}", atu.task_id, outcome);
        let input = json!({
            "task_id": atu.task_id,
            "action_digest": atu.action_digest,
            "effect_kind": atu.effect_kind,
            "iac_epoch": atu.iac_epoch,
        });
        let step = mission_journal::begin_step(
            state.as_ref(),
            mid,
            &atu.agent_pid,
            kind,
            &idem,
            &input,
            Some(json!({ "pate": true, "outcome": outcome })),
        )
        .map_err(|e| {
            ConnectorError::new(DenialReason::InternalError, format!("mission_begin: {e}"))
        })?;
        let receipt = json!({
            "outcome": outcome,
            "detail": detail,
            "task_id": atu.task_id,
        });
        let completed = mission_journal::complete_step(
            state.as_ref(),
            mid,
            &step.step_id,
            receipt,
        )
        .map_err(|e| {
            ConnectorError::new(DenialReason::InternalError, format!("mission_complete: {e}"))
        })?;
        let aapi = crate::substrate::aapi_bridge::record_atu_commit(
            state,
            atu,
            outcome,
            vec![atu.action_digest.clone()],
        );
        let moment = mint_moment_json(state, atu, outcome, &detail);
        let moment_id = moment.as_ref().and_then(|m| m.get("moment_id")).and_then(|v| v.as_str());
        bind_joined_refs(&mut finished, moment_id, &aapi);
        persist_atu(state, &finished, Some(outcome), moment_id);
        note_awd_observation(state, &finished, outcome, moment_id);
        return Ok(json!({
            "ok": true,
            "task_id": finished.task_id,
            "mission_id": mid,
            "step_id": completed.step_id,
            "aapi_audit": aapi,
            "moment": moment,
            "spine": finished.spine,
            "persisted": true,
        }));
    }
    let aapi = crate::substrate::aapi_bridge::record_atu_commit(
        state,
        atu,
        outcome,
        vec![atu.action_digest.clone()],
    );
    let moment = mint_moment_json(state, atu, outcome, &detail);
    let moment_id = moment.as_ref().and_then(|m| m.get("moment_id")).and_then(|v| v.as_str());
    bind_joined_refs(&mut finished, moment_id, &aapi);
    persist_atu(state, &finished, Some(outcome), moment_id);
    note_awd_observation(state, &finished, outcome, moment_id);
    Ok(json!({
        "ok": true,
        "task_id": finished.task_id,
        "outcome": finished.spine.outcome,
        "spine": finished.spine,
        "persisted": true,
        "aapi_audit": aapi,
        "moment": moment,
        "honesty": "no mission_id — ATU completed without journal step",
    }))
}

/// Admit already happened. Execute only on proceed, then complete that same task.
pub fn run_admitted_effect<F>(
    state: &SharedState,
    atu: &AugmentedTaskUnit,
    execute: F,
) -> Result<Value, ConnectorError>
where
    F: FnOnce(&AugmentedTaskUnit) -> Result<Value, String>,
{
    if !host_admission_allows_execution(atu.verdict) {
        let _ = complete_augmented_task(state, atu, "deny", json!({"observed": false}));
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "not_proceed",
        ));
    }
    match execute(atu) {
        Ok(mut detail) => {
            if detail.get("observed").is_none() {
                detail["observed"] = json!(true);
            }
            complete_augmented_task(state, atu, "ok", detail)
        }
        Err(error) => {
            let _ = complete_augmented_task(
                state,
                atu,
                "deny",
                json!({"observed": false, "error": error}),
            );
            Err(ConnectorError::new(DenialReason::PolicyDenied, error))
        }
    }
}

/// Admit agent registration. The call mints the contract, so a missing contract
/// is not a block. Ask stays open and does not execute. Block is an error.
pub fn admit_register(
    state: &SharedState,
    agent_pid: &str,
    arguments: &Value,
) -> Result<AugmentedTaskUnit, Value> {
    if let Err(error) = crate::kernel::intelligence_spec::assert_bound_skill_allows(
        state.as_ref(),
        agent_pid,
        "tool",
        "register_agent",
    ) {
        return Err(json!({
            "ok": false,
            "error": "bound_skill_denied",
            "denial_reason": error,
            "executed": false,
            "admits": false,
        }));
    }
    if let Err(error) = crate::kernel::address_cage::assert_agent_not_host_identity(agent_pid) {
        return Err(json!({
            "ok": false,
            "error": "host_identity_forbidden",
            "denial_reason": error,
            "executed": false,
            "admits": false,
        }));
    }
    let binding = action_binding::binding_for_tool(
        state.as_ref(),
        agent_pid,
        "lifecycle",
        "register_agent",
        arguments,
    );
    let risk = action_binding::infer_risk_class(&binding.operation, "register_agent");
    let decision = action_binding::autonomy_decide_register(state.as_ref(), &binding, risk);
    let atu = mint_atu(
        state,
        &binding,
        &decision,
        EffectKind::ToolDispatch,
        None,
        None,
    );
    let task_id = atu.task_id.clone();
    if atu.verdict == TaskVerdict::Block {
        return Err(json!({
            "ok": false,
            "error": decision.reason_code,
            "task_id": task_id,
            "executed": false,
            "admits": false,
        }));
    }
    if !host_admission_allows_execution(atu.verdict) {
        return Err(json!({
            "ok": false,
            "error": "not_proceed",
            "task_id": task_id,
            "executed": false,
            "admits": false,
        }));
    }
    crate::substrate::arc::governor::record_pate_admit(state, &atu).map_err(|error| {
        json!({
            "ok": false,
            "error": error.human_readable,
            "task_id": task_id.clone(),
            "executed": false,
            "admits": false,
        })
    })?;
    spend_gate_admit(state, agent_pid, &atu, "tool", None).map_err(|error| {
        json!({
            "ok": false,
            "error": error.human_readable,
            "task_id": task_id.clone(),
            "executed": false,
            "admits": false,
        })
    })?;
    Ok(atu)
}

/// Human close of an open Ask. Approving or denying HITL is not an outer-world tool,
/// and the subject may be `node` with no contract. The task Proceeds and the caller
/// must finish that same task after the request leaves the queue.
pub fn admit_human_close(
    state: &SharedState,
    agent_pid: &str,
    tool_name: &str,
    arguments: &Value,
) -> Result<AugmentedTaskUnit, Value> {
    if tool_name != "approve_hitl" && tool_name != "deny_hitl" {
        return Err(json!({
            "ok": false,
            "error": "not_a_human_close",
            "executed": false,
            "admits": false,
        }));
    }
    let binding = action_binding::binding_for_tool(
        state.as_ref(),
        agent_pid,
        "lifecycle",
        tool_name,
        arguments,
    );
    let decision = action_binding::AutonomyDecision {
        schema: action_binding::AUTONOMY_GATEWAY_SCHEMA.into(),
        verdict: action_binding::AutonomyVerdict::Allow,
        reason_code: "human_closed_the_open_ask".into(),
        action_digest: binding.digest_hex(),
        policy_version: binding.policy_version.clone(),
        risk_class: "tool".into(),
    };
    let atu = mint_atu(
        state,
        &binding,
        &decision,
        EffectKind::ToolDispatch,
        None,
        None,
    );
    if !host_admission_allows_execution(atu.verdict) {
        return Err(json!({
            "ok": false,
            "error": "not_proceed",
            "task_id": atu.task_id,
            "executed": false,
            "admits": false,
        }));
    }
    crate::substrate::arc::governor::record_pate_admit(state, &atu).map_err(|error| {
        json!({
            "ok": false,
            "error": error.human_readable,
            "task_id": atu.task_id.clone(),
            "executed": false,
            "admits": false,
        })
    })?;
    Ok(atu)
}

/// Admit a mutation. Ask stays open and does not execute. Block is an error.
pub fn require_proceed(
    state: &SharedState,
    agent_pid: &str,
    bridge_id: &str,
    tool_name: &str,
    arguments: &Value,
) -> Result<AugmentedTaskUnit, Value> {
    let atu = admit_tool(state, agent_pid, bridge_id, tool_name, arguments, None).map_err(|error| {
        json!({
            "ok": false,
            "error": error.human_readable,
            "executed": false,
            "admits": false,
        })
    })?;
    if !host_admission_allows_execution(atu.verdict) {
        return Err(json!({
            "ok": false,
            "error": "not_proceed",
            "task_id": atu.task_id,
            "executed": false,
            "admits": false,
        }));
    }
    Ok(atu)
}

/// Closes a Proceed task if the caller returns before finishing it.
/// Ask is left open. A second finish is ignored.
pub struct OpenProceed {
    state: SharedState,
    atu: Option<AugmentedTaskUnit>,
}

impl OpenProceed {
    pub fn arm(state: &SharedState, atu: &AugmentedTaskUnit) -> Self {
        Self {
            state: state.clone(),
            atu: Some(atu.clone()),
        }
    }

    pub fn disarm(&mut self) {
        self.atu = None;
    }

    pub fn finish_observed(&mut self, observed: bool) {
        let Some(atu) = self.atu.take() else {
            return;
        };
        if !host_admission_allows_execution(atu.verdict) {
            return;
        }
        let _ = run_admitted_effect(&self.state, &atu, |_| {
            if observed {
                Ok(json!({"observed": true}))
            } else {
                Err("unobserved".into())
            }
        });
    }
}

impl Drop for OpenProceed {
    fn drop(&mut self) {
        self.finish_observed(false);
    }
}

fn effect_observed(outcome: &str, detail: &Value) -> bool {
    if detail.get("observed").and_then(Value::as_bool) == Some(false) {
        return false;
    }
    detail.get("observed").and_then(Value::as_bool) == Some(true)
        || matches!(outcome, "ok" | "success" | "committed" | "observed")
}

fn stored_execution_attempts(state: &SharedState, task_id: &str) -> u32 {
    let Ok(es) = state.engine_store.lock() else {
        return 0;
    };
    es.folder_get(ATU_FOLDER, task_id)
        .ok()
        .flatten()
        .and_then(|value| value.pointer("/spine/execution_attempts").and_then(Value::as_u64))
        .unwrap_or(0) as u32
}

fn task_refs_from_detail(detail: &Value) -> TaskRefs {
    let text = |key: &str| {
        detail
            .get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(|value| value.to_string())
    };
    TaskRefs {
        operator_sub: text("operator_sub"),
        workload_id: text("workload_id"),
        generation_id: text("generation_id"),
        contract_digest: text("contract_digest"),
        grant_revision: text("grant_revision"),
        effect_archetype: text("effect_archetype"),
        hitl_request_id: text("hitl_request_id"),
        runtime_handle: text("runtime_handle"),
        artifact_digest: text("artifact_digest"),
        trace_id: text("trace_id"),
        receipt_id: text("receipt_id"),
        moment_id: text("moment_id"),
        awd_key: text("awd_key"),
        aapi_ref: text("aapi_ref"),
    }
}

fn bind_joined_refs(finished: &mut AugmentedTaskUnit, moment_id: Option<&str>, aapi: &Value) {
    if let Some(moment_id) = moment_id.filter(|id| !id.is_empty()) {
        finished.spine.moment_id = Some(moment_id.to_string());
    }
    finished.spine.awd_key = Some(format!("{}::{}", finished.agent_pid, finished.task_id));
    if let Some(record_id) = aapi.get("record_id").and_then(Value::as_str).filter(|id| !id.is_empty()) {
        finished.spine.aapi_ref = Some(record_id.to_string());
    }
    finished.spine.admits = false;
}

fn note_awd_observation(
    state: &SharedState,
    atu: &AugmentedTaskUnit,
    outcome: &str,
    moment_id: Option<&str>,
) {
    let verdict = serde_json::to_value(&atu.verdict)
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "absent".into());
    crate::substrate::awd::attach_observation(
        state,
        &atu.task_id,
        &atu.agent_pid,
        &verdict,
        outcome,
        moment_id,
    );
}

fn mint_moment_json(
    state: &SharedState,
    atu: &AugmentedTaskUnit,
    outcome: &str,
    detail: &Value,
) -> Option<Value> {
    crate::substrate::agent_memory::moment::record_atu_outcome(state.as_ref(), atu, outcome, detail)
        .map(|m| {
            json!({
                "moment_id": m.moment_id,
                "proof_level": m.current_proof_level.as_str(),
                "skeleton_id": m.skeleton_id,
            })
        })
}

pub fn posture_json() -> Value {
    json!({
        "schema": PATE_SCHEMA,
        "role": "ATU wrapper around ActionBinding — does not replace admit_*",
        "consistency_default": consistency_level_from_env(),
        "iac": "epoch checked at complete_augmented_task",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_task_id_stable_shape() {
        let id = mint_task_id("agt", "deadbeef", 3);
        assert!(id.starts_with("pate_3_"));
        assert_eq!(id.len(), "pate_3_".len() + 12);
    }

    #[test]
    fn map_verdict_ask() {
        let d = AutonomyDecision {
            schema: "t".into(),
            verdict: AutonomyVerdict::Ask,
            reason_code: "ask".into(),
            action_digest: "x".into(),
            policy_version: "1".into(),
            risk_class: "r2".into(),
        };
        assert_eq!(map_verdict(&d), TaskVerdict::AskHitl);
    }

    #[test]
    fn only_proceed_may_execute() {
        assert!(host_admission_allows_execution(TaskVerdict::Proceed));
        assert!(!host_admission_allows_execution(TaskVerdict::AskHitl));
        assert!(!host_admission_allows_execution(TaskVerdict::DeferRedo));
        assert!(!host_admission_allows_execution(TaskVerdict::Quarantine));
        assert!(!host_admission_allows_execution(TaskVerdict::Block));
    }

    fn sample_atu(task_id: &str, verdict: TaskVerdict) -> AugmentedTaskUnit {
        AugmentedTaskUnit {
            schema: PATE_SCHEMA.into(),
            task_id: task_id.into(),
            agent_pid: "agent-1".into(),
            broker_epoch: 4,
            iac_epoch: 1,
            consistency_level: 2,
            effect_kind: EffectKind::ToolDispatch,
            action_digest: "digest-1".into(),
            tool_footprint: ToolFootprint {
                idempotent: false,
                ..ToolFootprint::default()
            },
            mission_id: Some(format!("mission:{task_id}")),
            mission_step_id: None,
            verdict,
            autonomy: None,
            minted_at_ms: 1,
            context_ref: None,
            spine: TaskSpine {
                admits: true,
                ..TaskSpine::default()
            },
        }
    }

    #[test]
    fn complete_task_record_commits_once_and_releases_when_unobserved() {
        let refs = TaskRefs {
            receipt_id: Some("receipt:pate-1".into()),
            trace_id: Some("trace:pate-1".into()),
            moment_id: Some("moment:pate-1".into()),
            awd_key: Some("agent-1::pate-1".into()),
            aapi_ref: Some("aapi:pate-1".into()),
            effect_archetype: Some("issue_credential".into()),
            ..TaskRefs::default()
        };
        let committed = finish_task_record(
            sample_atu("pate-1", TaskVerdict::Proceed),
            &TaskAttempt {
                idempotency_key: "rotate-once".into(),
                mutating: true,
                observed: true,
            },
            refs,
        )
        .expect("commit");
        assert_eq!(committed.spine.spend, "committed");
        assert_eq!(committed.spine.execution_attempts, 1);
        assert_eq!(committed.spine.receipt_id.as_deref(), Some("receipt:pate-1"));
        assert_eq!(committed.spine.awd_key.as_deref(), Some("agent-1::pate-1"));
        assert!(!committed.spine.admits);
        assert_eq!(committed.mission_id.as_deref(), Some("mission:pate-1"));

        let mut again = committed.clone();
        let err = finish_task_record(
            again.clone(),
            &TaskAttempt {
                idempotency_key: "rotate-once".into(),
                mutating: true,
                observed: true,
            },
            TaskRefs::default(),
        )
        .expect_err("one attempt");
        assert_eq!(err, "one_execution_attempt");
        again.spine.execution_attempts = 0;
        let missing = finish_task_record(
            again,
            &TaskAttempt {
                idempotency_key: "  ".into(),
                mutating: true,
                observed: true,
            },
            TaskRefs::default(),
        )
        .expect_err("key");
        assert_eq!(missing, "idempotency_required");

        let released = finish_task_record(
            sample_atu("pate-2", TaskVerdict::Block),
            &TaskAttempt {
                idempotency_key: "blocked".into(),
                mutating: true,
                observed: true,
            },
            TaskRefs {
                receipt_id: Some("receipt:pate-2".into()),
                ..TaskRefs::default()
            },
        )
        .expect("release");
        assert_eq!(released.spine.spend, "released");
        assert_eq!(released.spine.execution_attempts, 0);
        assert!(released.spine.receipt_id.is_none());
        assert_ne!(released.task_id, committed.task_id);
        assert_ne!(released.spine.receipt_id, committed.spine.receipt_id);
    }

    #[test]
    fn older_atu_without_spine_still_loads() {
        let raw = r#"{
            "schema":"connector.pate.atu.v1",
            "task_id":"pate_1_abc",
            "agent_pid":"agent-1",
            "broker_epoch":1,
            "iac_epoch":1,
            "consistency_level":2,
            "effect_kind":"tool_dispatch",
            "action_digest":"digest",
            "tool_footprint":{"read_refs":[],"write_refs":[],"idempotent":false,"inverse_registered":false,"requires_hitl":false,"reversibility":"","conp_capability":null,"risk_class":""},
            "mission_id":null,
            "mission_step_id":null,
            "verdict":"proceed",
            "autonomy":null,
            "minted_at_ms":1
        }"#;
        let atu: AugmentedTaskUnit = serde_json::from_str(raw).expect("legacy record");
        assert_eq!(atu.task_id, "pate_1_abc");
        assert_eq!(atu.spine.execution_attempts, 0);
        assert!(!atu.spine.admits);
    }
}
