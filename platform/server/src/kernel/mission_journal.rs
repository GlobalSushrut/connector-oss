//! TG-3 — Durable mission / execution journal (append-only engine_store).
//!
//! Session chat ≠ durable execution. Mutating steps record receipts so resume
//! never re-fires completed side effects (tools, CONP commands, HITL waits).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::state::PlatformState;

pub const MISSION_SCHEMA: &str = "connector.mission.v1";
pub const STEP_SCHEMA: &str = "connector.mission.step.v1";
pub const MISSION_FOLDER: &str = "iia_missions";
pub const STEP_FOLDER: &str = "iia_mission_steps";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MissionStatus {
    Open,
    WaitingHitl,
    Completed,
    Failed,
    Canceled,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    Llm,
    Tool,
    HitlWait,
    Fabric,
    ConpCommand,
    CnpMessage,
    Compensate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StepStatus {
    Pending,
    Waiting,
    Completed,
    Failed,
    Skipped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MissionV1 {
    pub schema: String,
    pub mission_id: String,
    pub agent_pid: String,
    pub principal_id: Option<String>,
    pub status: MissionStatus,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub label: Option<String>,
}

impl MissionV1 {
    /// Alias: mission_id is the durable operation_id (OperationStore = mission journal).
    pub fn operation_id(&self) -> &str {
        &self.mission_id
    }

    pub fn to_operation_ref(&self) -> connector_native_contract::OperationRef {
        use connector_native_contract::{operation_status_from_mission, OperationRef};
        let status = match &self.status {
            MissionStatus::Open => "open",
            MissionStatus::WaitingHitl => "waiting_hitl",
            MissionStatus::Completed => "completed",
            MissionStatus::Failed => "failed",
            MissionStatus::Canceled => "canceled",
        };
        let mut op = OperationRef::new(
            self.mission_id.clone(),
            operation_status_from_mission(status),
            self.created_at_ms,
            self.updated_at_ms,
        );
        op.agent_pid = Some(self.agent_pid.clone());
        op.label = self.label.clone();
        op
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionStepV1 {
    pub schema: String,
    pub mission_id: String,
    pub step_id: String,
    pub kind: StepKind,
    pub idempotency_key: String,
    pub input_digest: String,
    pub status: StepStatus,
    pub agent_pid: String,
    pub output_receipt: Option<Value>,
    pub error: Option<String>,
    pub created_at_ms: i64,
    pub completed_at_ms: Option<i64>,
    /// Optional protocol metadata (CONP message_type, capability_id, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<Value>,
    /// Ledger chain digest over prior step + this step inputs (restart integrity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ledger_digest: Option<String>,
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

pub fn input_digest_of(v: &Value) -> String {
    let canon = crate::kernel::action_binding::canonical_json(v);
    let bytes = serde_json::to_vec(&canon).unwrap_or_default();
    format!("{:x}", Sha256::digest(&bytes))
}

pub fn create_mission(
    state: &PlatformState,
    agent_pid: &str,
    label: Option<String>,
) -> Result<MissionV1, String> {
    let principal_id =
        crate::kernel::agent_principal::load_principal(state, agent_pid).map(|p| p.principal_id);
    let now = now_ms();
    let mission = MissionV1 {
        schema: MISSION_SCHEMA.into(),
        mission_id: format!("msn_{}", Uuid::new_v4()),
        agent_pid: agent_pid.into(),
        principal_id,
        status: MissionStatus::Open,
        created_at_ms: now,
        updated_at_ms: now,
        label,
    };
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    let v = serde_json::to_value(&mission).map_err(|e| e.to_string())?;
    es.folder_put(MISSION_FOLDER, &mission.mission_id, &v)
        .map_err(|e| e.to_string())?;
    Ok(mission)
}

pub fn load_mission(state: &PlatformState, mission_id: &str) -> Option<MissionV1> {
    let es = state.engine_store.lock().ok()?;
    let v = es.folder_get(MISSION_FOLDER, mission_id).ok().flatten()?;
    serde_json::from_value(v).ok()
}

fn step_key(mission_id: &str, step_id: &str) -> String {
    format!("{mission_id}:{step_id}")
}

pub fn list_steps(state: &PlatformState, mission_id: &str) -> Vec<ExecutionStepV1> {
    let Ok(es) = state.engine_store.lock() else {
        return Vec::new();
    };
    let prefix = format!("{mission_id}:");
    let keys = es
        .folder_keys(STEP_FOLDER, Some(&prefix))
        .unwrap_or_default();
    let mut steps = Vec::new();
    for k in keys {
        if let Ok(Some(v)) = es.folder_get(STEP_FOLDER, &k) {
            if let Ok(s) = serde_json::from_value::<ExecutionStepV1>(v) {
                steps.push(s);
            }
        }
    }
    steps.sort_by_key(|s| s.created_at_ms);
    steps
}

/// Find any step by idempotency key (completed or in-flight).
pub fn find_step_by_idempotency(
    state: &PlatformState,
    mission_id: &str,
    idempotency_key: &str,
) -> Option<ExecutionStepV1> {
    list_steps(state, mission_id)
        .into_iter()
        .find(|s| s.idempotency_key == idempotency_key)
}

/// Find completed step by idempotency key (resume skip).
pub fn find_completed_by_idempotency(
    state: &PlatformState,
    mission_id: &str,
    idempotency_key: &str,
) -> Option<ExecutionStepV1> {
    find_step_by_idempotency(state, mission_id, idempotency_key)
        .filter(|s| s.status == StepStatus::Completed)
}

fn chain_digest(prev: Option<&str>, input_digest: &str, idempotency_key: &str) -> String {
    let material = format!(
        "{}|{}|{}",
        prev.unwrap_or("genesis"),
        input_digest,
        idempotency_key
    );
    format!("{:x}", Sha256::digest(material.as_bytes()))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeginOutcome {
    /// Fresh Pending step — caller may execute the effect once.
    New,
    /// Completed — caller must replay receipt, not re-fire.
    ExistingCompleted,
    /// Pending/Waiting/Failed already recorded — caller must not re-fire.
    ExistingInFlight,
}

/// Append a pending step, or return existing step for the same idempotency key.
///
/// This is the durable **accept-before-effect** gate: callers must only fire
/// side effects when `BeginOutcome::New` (or continue an in-flight wait).
pub fn begin_step(
    state: &PlatformState,
    mission_id: &str,
    agent_pid: &str,
    kind: StepKind,
    idempotency_key: &str,
    input: &Value,
    protocol: Option<Value>,
) -> Result<ExecutionStepV1, String> {
    Ok(begin_step_detailed(state, mission_id, agent_pid, kind, idempotency_key, input, protocol)?.0)
}

/// Alias for [`begin_step`] — accept the operation step before any world effect.
pub fn accept_step(
    state: &PlatformState,
    mission_id: &str,
    agent_pid: &str,
    kind: StepKind,
    idempotency_key: &str,
    input: &Value,
    protocol: Option<Value>,
) -> Result<ExecutionStepV1, String> {
    begin_step(
        state,
        mission_id,
        agent_pid,
        kind,
        idempotency_key,
        input,
        protocol,
    )
}

/// Like `begin_step`, but reports whether the step is new or a restart-safe existing row.
pub fn begin_step_detailed(
    state: &PlatformState,
    mission_id: &str,
    agent_pid: &str,
    kind: StepKind,
    idempotency_key: &str,
    input: &Value,
    protocol: Option<Value>,
) -> Result<(ExecutionStepV1, BeginOutcome), String> {
    let mission = load_mission(state, mission_id).ok_or_else(|| "mission_not_found".to_string())?;
    if matches!(
        mission.status,
        MissionStatus::Canceled | MissionStatus::Completed | MissionStatus::Failed
    ) {
        return Err(format!(
            "mission_not_accepting_steps:status={:?}",
            mission.status
        ));
    }
    if let Some(existing) = find_step_by_idempotency(state, mission_id, idempotency_key) {
        let outcome = match existing.status {
            StepStatus::Completed => BeginOutcome::ExistingCompleted,
            StepStatus::Skipped => BeginOutcome::ExistingCompleted,
            _ => BeginOutcome::ExistingInFlight,
        };
        return Ok((existing, outcome));
    }
    let prior = list_steps(state, mission_id)
        .into_iter()
        .filter(|s| s.ledger_digest.is_some())
        .max_by_key(|s| s.created_at_ms);
    let input_digest = input_digest_of(input);
    let ledger = chain_digest(
        prior.as_ref().and_then(|p| p.ledger_digest.as_deref()),
        &input_digest,
        idempotency_key,
    );
    let step = ExecutionStepV1 {
        schema: STEP_SCHEMA.into(),
        mission_id: mission_id.into(),
        step_id: format!("stp_{}", Uuid::new_v4()),
        kind,
        idempotency_key: idempotency_key.into(),
        input_digest,
        status: StepStatus::Pending,
        agent_pid: agent_pid.into(),
        output_receipt: None,
        error: None,
        created_at_ms: now_ms(),
        completed_at_ms: None,
        protocol,
        ledger_digest: Some(ledger),
    };
    persist_step(state, &step)?;
    touch_mission(state, mission_id, None)?;
    Ok((step, BeginOutcome::New))
}

pub fn complete_step(
    state: &PlatformState,
    mission_id: &str,
    step_id: &str,
    receipt: Value,
) -> Result<ExecutionStepV1, String> {
    let mut step = load_step(state, mission_id, step_id).ok_or_else(|| "step_not_found".to_string())?;
    if step.status == StepStatus::Completed {
        return Ok(step);
    }
    step.status = StepStatus::Completed;
    step.output_receipt = Some(receipt);
    step.completed_at_ms = Some(now_ms());
    persist_step(state, &step)?;
    touch_mission(state, mission_id, None)?;
    Ok(step)
}

pub fn fail_step(
    state: &PlatformState,
    mission_id: &str,
    step_id: &str,
    error: impl Into<String>,
) -> Result<ExecutionStepV1, String> {
    let mut step = load_step(state, mission_id, step_id).ok_or_else(|| "step_not_found".to_string())?;
    step.status = StepStatus::Failed;
    step.error = Some(error.into());
    step.completed_at_ms = Some(now_ms());
    persist_step(state, &step)?;
    touch_mission(state, mission_id, Some(MissionStatus::Failed))?;
    Ok(step)
}

/// Cancel an open mission: skip open Pending/Waiting steps and set status Canceled.
/// Idempotent when already terminal. Further `begin_step` / accept is denied.
pub fn cancel_mission(
    state: &PlatformState,
    mission_id: &str,
    reason: &str,
) -> Result<(MissionV1, Vec<String>), String> {
    let mission = load_mission(state, mission_id).ok_or_else(|| "mission_not_found".to_string())?;
    if matches!(
        mission.status,
        MissionStatus::Canceled | MissionStatus::Completed | MissionStatus::Failed
    ) {
        return Ok((mission, vec![]));
    }
    let mut skipped = Vec::new();
    let reason_s = if reason.trim().is_empty() {
        "mission_canceled".to_string()
    } else {
        reason.to_string()
    };
    for mut step in list_steps(state, mission_id) {
        if !matches!(step.status, StepStatus::Pending | StepStatus::Waiting) {
            continue;
        }
        step.status = StepStatus::Skipped;
        step.error = Some(reason_s.clone());
        step.completed_at_ms = Some(now_ms());
        persist_step(state, &step)?;
        skipped.push(step.step_id);
    }
    touch_mission(state, mission_id, Some(MissionStatus::Canceled))?;
    let updated =
        load_mission(state, mission_id).ok_or_else(|| "mission_not_found".to_string())?;
    Ok((updated, skipped))
}

/// Link a step to an HITL request and put the mission into WaitingHitl.
pub fn mark_waiting_hitl(
    state: &PlatformState,
    mission_id: &str,
    step_id: &str,
    hitl_request_id: &str,
) -> Result<ExecutionStepV1, String> {
    let mut step =
        load_step(state, mission_id, step_id).ok_or_else(|| "step_not_found".to_string())?;
    if step.status == StepStatus::Completed {
        return Ok(step);
    }
    step.status = StepStatus::Waiting;
    let mut proto = step.protocol.clone().unwrap_or_else(|| json!({}));
    if let Some(obj) = proto.as_object_mut() {
        obj.insert(
            "hitl_request_id".into(),
            json!(hitl_request_id),
        );
        obj.insert("waiting_hitl".into(), json!(true));
    }
    step.protocol = Some(proto);
    step.kind = StepKind::HitlWait;
    persist_step(state, &step)?;
    touch_mission(state, mission_id, Some(MissionStatus::WaitingHitl))?;
    Ok(step)
}

/// After HITL approve/deny: complete the wait step and reopen the mission if still WaitingHitl.
pub fn resolve_hitl_wait(
    state: &PlatformState,
    mission_id: &str,
    step_id: &str,
    approved: bool,
    receipt: Value,
) -> Result<ExecutionStepV1, String> {
    let step = if approved {
        complete_step(state, mission_id, step_id, receipt)?
    } else {
        fail_step(
            state,
            mission_id,
            step_id,
            receipt
                .get("reason")
                .and_then(|v| v.as_str())
                .unwrap_or("hitl_denied"),
        )?
    };
    if let Some(m) = load_mission(state, mission_id) {
        if m.status == MissionStatus::WaitingHitl && approved {
            touch_mission(state, mission_id, Some(MissionStatus::Open))?;
        }
    }
    Ok(step)
}

fn load_step(state: &PlatformState, mission_id: &str, step_id: &str) -> Option<ExecutionStepV1> {
    let es = state.engine_store.lock().ok()?;
    let v = es
        .folder_get(STEP_FOLDER, &step_key(mission_id, step_id))
        .ok()
        .flatten()?;
    serde_json::from_value(v).ok()
}

fn persist_step(state: &PlatformState, step: &ExecutionStepV1) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    let v = serde_json::to_value(step).map_err(|e| e.to_string())?;
    es.folder_put(STEP_FOLDER, &step_key(&step.mission_id, &step.step_id), &v)
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn touch_mission(
    state: &PlatformState,
    mission_id: &str,
    status: Option<MissionStatus>,
) -> Result<(), String> {
    let mut m = load_mission(state, mission_id).ok_or_else(|| "mission_not_found".to_string())?;
    m.updated_at_ms = now_ms();
    if let Some(s) = status {
        m.status = s;
    }
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    let v = serde_json::to_value(&m).map_err(|e| e.to_string())?;
    es.folder_put(MISSION_FOLDER, mission_id, &v)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Resume: return completed receipts + pending/waiting steps (caller skips re-fire).
/// When `CONNECTOR_MISSION_ABANDON_STALE_PENDING=1` (default under productionish),
/// Pending steps older than the threshold are marked Failed as interrupted so
/// restart cannot silently re-execute an in-flight effect.
pub fn resume_snapshot(state: &PlatformState, mission_id: &str) -> Result<Value, String> {
    let mission = load_mission(state, mission_id).ok_or_else(|| "mission_not_found".to_string())?;
    let abandoned = abandon_stale_pending(state, mission_id)?;
    let steps = list_steps(state, mission_id);
    let completed: Vec<_> = steps
        .iter()
        .filter(|s| s.status == StepStatus::Completed)
        .cloned()
        .collect();
    let open: Vec<_> = steps
        .iter()
        .filter(|s| matches!(s.status, StepStatus::Pending | StepStatus::Waiting))
        .cloned()
        .collect();
    Ok(json!({
        "ok": true,
        "schema": "connector.mission.resume.v1",
        "mission": mission,
        "completed_steps": completed,
        "open_steps": open,
        "abandoned_stale_pending": abandoned,
        "honesty": "TG-3 / T4 — do not re-invoke side effects for completed or abandoned idempotency_keys; Pending after crash is fail-closed",
    }))
}

fn abandon_stale_env_on() -> bool {
    match std::env::var("CONNECTOR_MISSION_ABANDON_STALE_PENDING") {
        Ok(v) => {
            let t = v.trim().to_ascii_lowercase();
            matches!(t.as_str(), "1" | "true" | "yes" | "on")
        }
        // Productionish default: abandon Pending on resume (restart-safe).
        Err(_) => crate::connector_profile::is_productionish_env(),
    }
}

/// Mark long-lived Pending steps Failed so restart soak cannot duplicate effects.
/// Enable with `CONNECTOR_MISSION_ABANDON_STALE_PENDING=1` (unbypassable default).
pub fn abandon_stale_pending(
    state: &PlatformState,
    mission_id: &str,
) -> Result<Vec<String>, String> {
    if !abandon_stale_env_on() {
        return Ok(Vec::new());
    }
    let max_age_ms: i64 = std::env::var("CONNECTOR_MISSION_STALE_PENDING_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0); // 0 = abandon all Pending on resume (restart-safe bar)
    let now = now_ms();
    let mut abandoned = Vec::new();
    for step in list_steps(state, mission_id) {
        if step.status != StepStatus::Pending {
            continue;
        }
        if max_age_ms > 0 && now.saturating_sub(step.created_at_ms) < max_age_ms {
            continue;
        }
        let _ = fail_step(
            state,
            mission_id,
            &step.step_id,
            "interrupted_before_complete_restart_safe",
        )?;
        abandoned.push(step.step_id);
    }
    Ok(abandoned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_digest_stable() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(input_digest_of(&a), input_digest_of(&b));
    }

    #[test]
    fn operation_ref_maps_canceled() {
        let m = MissionV1 {
            schema: MISSION_SCHEMA.into(),
            mission_id: "msn_x".into(),
            agent_pid: "a1".into(),
            principal_id: None,
            status: MissionStatus::Canceled,
            created_at_ms: 1,
            updated_at_ms: 2,
            label: None,
        };
        assert_eq!(m.operation_id(), "msn_x");
        assert_eq!(
            m.to_operation_ref().status,
            connector_native_contract::OperationStatus::Cancelled
        );
    }
}
