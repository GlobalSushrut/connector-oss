//! VerifiedProcedureCapsule store — executable methods, not explanations.

use connector_trust::{
    ProcedureStep, TrustTier, VerifiedProcedureCapsule, PROCEDURE_CAPSULE_SCHEMA,
};

use crate::state::PlatformState;

use super::trust_firewall;
use super::{now_ms, FOLDER_PROCEDURES};

fn proc_key(agent_pid: &str, procedure_id: &str) -> String {
    format!("{agent_pid}:{procedure_id}")
}

fn skill_key(agent_pid: &str, skill_id: &str) -> String {
    format!("skill:{agent_pid}:{skill_id}")
}

pub fn put(
    state: &PlatformState,
    agent_pid: &str,
    procedure_id: &str,
    skill_id: &str,
    procedure_version: &str,
    steps: Vec<ProcedureStep>,
    provenance: &str,
    trust: TrustTier,
) -> Result<VerifiedProcedureCapsule, String> {
    let envelope = trust_firewall::bind_envelope(
        procedure_id,
        agent_pid,
        provenance,
        trust,
        "verified_procedure",
        vec![],
        None,
        Some(skill_id.into()),
        Some(now_ms()),
        None,
    );
    let cap = VerifiedProcedureCapsule {
        schema: PROCEDURE_CAPSULE_SCHEMA.into(),
        procedure_id: procedure_id.into(),
        skill_id: skill_id.into(),
        procedure_version: procedure_version.into(),
        agent_pid: agent_pid.into(),
        preconditions: vec![],
        steps,
        required_evidence: vec![],
        verification_points: vec![],
        exit_conditions: vec![],
        provenance: provenance.into(),
        successful_runs: 0,
        failure_modes: vec![],
        envelope,
    };
    let mut es = state
        .engine_store
        .lock()
        .map_err(|e| format!("engine_store lock: {e}"))?;
    let val = serde_json::to_value(&cap).map_err(|e| format!("serialize: {e}"))?;
    es.folder_put(FOLDER_PROCEDURES, &proc_key(agent_pid, procedure_id), &val)
        .map_err(|e| format!("put procedure: {e}"))?;
    es.folder_put(
        FOLDER_PROCEDURES,
        &skill_key(agent_pid, skill_id),
        &serde_json::json!({ "procedure_id": procedure_id, "version": procedure_version }),
    )
    .map_err(|e| format!("put skill index: {e}"))?;
    Ok(cap)
}

pub fn select_for_skill(
    state: &PlatformState,
    agent_pid: &str,
    skill_id: Option<&str>,
) -> Option<VerifiedProcedureCapsule> {
    let skill = skill_id?;
    let es = state.engine_store.lock().ok()?;
    let idx = es
        .folder_get(FOLDER_PROCEDURES, &skill_key(agent_pid, skill))
        .ok()
        .flatten()?;
    let pid = idx.get("procedure_id")?.as_str()?;
    let v = es
        .folder_get(FOLDER_PROCEDURES, &proc_key(agent_pid, pid))
        .ok()
        .flatten()?;
    serde_json::from_value(v).ok()
}

pub fn load(
    state: &PlatformState,
    agent_pid: &str,
    procedure_id: &str,
) -> Option<VerifiedProcedureCapsule> {
    let es = state.engine_store.lock().ok()?;
    let v = es
        .folder_get(FOLDER_PROCEDURES, &proc_key(agent_pid, procedure_id))
        .ok()
        .flatten()?;
    serde_json::from_value(v).ok()
}

/// Next Admit-able step description for DAL Plan (LLM-optional).
pub fn next_step_payload(cap: &VerifiedProcedureCapsule, step_index: usize) -> Option<serde_json::Value> {
    let step = cap.steps.get(step_index)?;
    Some(serde_json::json!({
        "procedure_id": cap.procedure_id,
        "procedure_version": cap.procedure_version,
        "step_index": step_index,
        "step_id": step.step_id,
        "kind": step.kind,
        "description": step.description,
        "tool_or_capability": step.tool_or_capability,
        "required_evidence": step.required_evidence,
    }))
}
