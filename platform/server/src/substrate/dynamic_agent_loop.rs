//! Dynamic Agent Loop (DAL) — CID-only durable run state.
//!
//! Mission journal owns lineage; VAC owns evidence packets; NS FS owns bounded
//! working RAM. This module never stores raw `reasoning_content` or duplicate
//! memory text — only CIDs, digests, and journal refs.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{ConnectorError, DenialReason};
use crate::kernel::mission_journal;
use crate::state::{PlatformState, SharedState};

pub const RUN_STATE_SCHEMA: &str = "connector.dal.run_state.v1";
pub const RUN_FOLDER: &str = "dal_run_states";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentPhase {
    Observe,
    Recall,
    Plan,
    Propose,
    Admit,
    Act,
    Verify,
    Replan,
    HitlWait,
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    GoalSatisfied,
    Blocked,
    BudgetExhausted,
    NoProgress,
    Deadline,
    SafetyHalt,
    OperatorCancel,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct WorkingSet {
    pub context_cids: Vec<String>,
    pub staged_candidate_cids: Vec<String>,
    pub compaction_summary_cid: Option<String>,
    pub token_budget: u64,
    /// Last CRK InfluenceManifest id bound to this run's Recall (≠ SVF ContextManifest).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub influence_manifest_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub moment_range_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub procedure_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RunBudgets {
    pub max_steps: u32,
    pub steps_used: u32,
    pub max_tool_calls: u32,
    pub tool_calls_used: u32,
    pub max_tokens: u64,
    pub tokens_used: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProgressSignals {
    pub last_verify_ok: bool,
    pub consecutive_no_progress: u32,
    pub last_receipt_cid: Option<String>,
}

/// Compact checkpoint — CIDs and refs only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRunState {
    pub schema: String,
    pub run_id: String,
    pub mission_id: String,
    pub agent_pid: String,
    pub goal_digest: String,
    pub phase: AgentPhase,
    pub frontier: Vec<String>,
    pub observation_cids: Vec<String>,
    pub working_memory: WorkingSet,
    pub pending_action_digest: Option<String>,
    pub pending_approval_digest: Option<String>,
    pub broker_epoch: u64,
    pub iac_epoch: u64,
    pub context_revision: u64,
    pub vac_read_set_epoch: u64,
    pub budgets: RunBudgets,
    pub progress: ProgressSignals,
    pub stop_reason: Option<StopReason>,
    pub updated_at_ms: i64,
}

impl AgentRunState {
    pub fn new(agent_pid: &str, mission_id: &str, goal: &str) -> Self {
        let now = now_ms();
        let goal_digest = digest_hex(goal.as_bytes());
        let run_id = format!(
            "dal_{}",
            &digest_hex(format!("{agent_pid}|{mission_id}|{now}").as_bytes())[..16]
        );
        Self {
            schema: RUN_STATE_SCHEMA.into(),
            run_id,
            mission_id: mission_id.into(),
            agent_pid: agent_pid.into(),
            goal_digest,
            phase: AgentPhase::Observe,
            frontier: Vec::new(),
            observation_cids: Vec::new(),
            working_memory: WorkingSet {
                token_budget: 16_000,
                ..Default::default()
            },
            pending_action_digest: None,
            pending_approval_digest: None,
            broker_epoch: 0,
            iac_epoch: 0,
            context_revision: 0,
            vac_read_set_epoch: 0,
            budgets: RunBudgets {
                max_steps: 100,
                max_tool_calls: 40,
                max_tokens: 200_000,
                ..Default::default()
            },
            progress: ProgressSignals::default(),
            stop_reason: None,
            updated_at_ms: now,
        }
    }

    pub fn advance(&mut self, phase: AgentPhase) {
        self.phase = phase;
        self.budgets.steps_used = self.budgets.steps_used.saturating_add(1);
        self.updated_at_ms = now_ms();
    }

    pub fn stop(&mut self, reason: StopReason) {
        self.phase = AgentPhase::Stopped;
        self.stop_reason = Some(reason);
        self.updated_at_ms = now_ms();
    }

    pub fn budget_exhausted(&self) -> bool {
        self.budgets.steps_used >= self.budgets.max_steps
            || self.budgets.tool_calls_used >= self.budgets.max_tool_calls
            || self.budgets.tokens_used >= self.budgets.max_tokens
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

fn digest_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Persist run state under engine_store (CID-only JSON).
pub fn checkpoint(state: &PlatformState, run: &AgentRunState) -> Result<(), ConnectorError> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| ConnectorError::internal("engine_store lock"))?;
    es.folder_put(RUN_FOLDER, &run.run_id, &serde_json::to_value(run).unwrap_or(Value::Null))
        .map_err(|e| ConnectorError::internal(format!("dal_checkpoint: {e}")))?;
    Ok(())
}

pub fn load(state: &PlatformState, run_id: &str) -> Result<Option<AgentRunState>, ConnectorError> {
    let es = state
        .engine_store
        .lock()
        .map_err(|_| ConnectorError::internal("engine_store lock"))?;
    let v = es
        .folder_get(RUN_FOLDER, run_id)
        .map_err(|e| ConnectorError::internal(format!("dal_load: {e}")))?;
    Ok(v.and_then(|x| serde_json::from_value(x).ok()))
}

/// Start a DAL run bound to a mission (creates mission if missing).
pub fn start_run(
    state: &SharedState,
    agent_pid: &str,
    goal: &str,
    mission_id: Option<String>,
) -> Result<AgentRunState, ConnectorError> {
    let mid = match mission_id.filter(|s| !s.trim().is_empty()) {
        Some(m) => m,
        None => mission_journal::create_mission(state.as_ref(), agent_pid, Some("dal".into()))
            .map(|m| m.mission_id)
            .map_err(|e| {
                ConnectorError::new(DenialReason::InternalError, format!("dal_mission: {e}"))
            })?,
    };
    let cell = state.cells.get_or_create(agent_pid);
    let mut run = AgentRunState::new(agent_pid, &mid, goal);
    refresh_epochs(state, &mut run);
    run.iac_epoch = cell.current_epoch();
    run.vac_read_set_epoch = cell
        .read_set
        .read()
        .map(|r| r.stamped_epoch)
        .unwrap_or(0);
    checkpoint(state.as_ref(), &run)?;
    Ok(run)
}

/// Stamp live broker / IAC / read-set epochs onto the run (SvfEpoch coherence).
pub fn refresh_epochs(state: &SharedState, run: &mut AgentRunState) {
    run.broker_epoch =
        crate::substrate::llm_context_broker::current_generation(state, &run.agent_pid);
    let cell = state.cells.get_or_create(&run.agent_pid);
    run.iac_epoch = cell.current_epoch();
    run.vac_read_set_epoch = cell
        .read_set
        .read()
        .map(|r| r.stamped_epoch)
        .unwrap_or(0);
    run.updated_at_ms = now_ms();
}

/// Live SvfEpoch for this run (broker · iac · policy=context_revision).
pub fn svf_epoch(run: &AgentRunState) -> connector_trust::SvfEpoch {
    connector_trust::SvfEpoch::new(run.broker_epoch, run.iac_epoch, run.context_revision)
}

/// A cease bumps the broker generation. A loop stamped on the old generation must stop,
/// even if the model still wants another step.
pub fn loop_must_stop(stamped_epoch: u64, live_epoch: u64) -> bool {
    stamped_epoch != 0 && live_epoch != stamped_epoch
}

/// Refuse Act when CIP inhibits or broker epoch drifted since stamp.
pub fn assert_turn_allowed(
    state: &SharedState,
    run: &AgentRunState,
) -> Result<(), ConnectorError> {
    if matches!(run.phase, AgentPhase::Stopped | AgentPhase::HitlWait) {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!("dal_phase_blocks_turn:{:?}", run.phase),
        )
        .with_denied_resource("dal.turn"));
    }
    let cip = crate::substrate::cip_executive::project_from_run(run);
    if crate::substrate::cip_executive::should_inhibit_effect(&cip) {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "cip_inhibit_effect",
        )
        .with_denied_resource("dal.cip")
        .with_hint("HITL wait or stopped — no auto-dispatch"));
    }
    let live = crate::substrate::llm_context_broker::current_generation(state, &run.agent_pid);
    if run.broker_epoch != 0 && live != run.broker_epoch {
        let _ = crate::substrate::spend_cease::note_post_cease_stale_admit(state, &run.agent_pid);
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!("broker_epoch_mismatch: run={} live={live}", run.broker_epoch),
        )
        .with_denied_resource("dal.broker_epoch")
        .with_hint("Refresh DAL run after quarantine / SpendCease / broker generation bump"));
    }
    crate::substrate::effect_exclusivity::assert_effect_exclusivity_ready(
        &run.agent_pid,
        state.as_ref(),
    )
    .map_err(|v| {
        ConnectorError::new(
            DenialReason::PolicyDenied,
            v.get("denial_reason")
                .or_else(|| v.get("error"))
                .and_then(|x| x.as_str())
                .unwrap_or("effect_exclusivity"),
        )
        .with_denied_resource("dal.exclusivity")
    })?;
    Ok(())
}

/// One DAL-owned turn: PROJECT context → governed proposals → OBSERVE receipts → LTL stitch.
/// Ring-1: proposals only; no Talk auto-dispatch. Tools sandwich stays in `tools.rs`.
pub async fn run_turn(
    state: &SharedState,
    run: &mut AgentRunState,
    tool_calls: &[Value],
    assistant_text: Option<&str>,
    reasoning: Option<&str>,
) -> Result<Value, ConnectorError> {
    let live = crate::substrate::llm_context_broker::current_generation(state, &run.agent_pid);
    if loop_must_stop(run.broker_epoch, live) {
        run.stop(StopReason::OperatorCancel);
        let _ = checkpoint(state.as_ref(), run);
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "operator_cease: this loop stopped. The model does not get another step.",
        )
        .with_denied_resource("dal.cease"));
    }
    refresh_epochs(state, run);
    assert_turn_allowed(state, run)?;

    // Observe / Recall: SEMANTICIZE + PROJECT + RangeGuard window (eligibility-first).
    run.advance(AgentPhase::Observe);
    let _ = crate::substrate::svf::semanticize_agent(state, &run.agent_pid);
    let projection = crate::substrate::svf::gateway_injection_block(state, &run.agent_pid);
    let tool_stubs = crate::substrate::svf::gateway_tool_stub_block(state, &run.agent_pid);
    run.advance(AgentPhase::Recall);

    let action_digest = run
        .pending_action_digest
        .clone()
        .unwrap_or_else(|| run.goal_digest.clone());
    let cue = crate::substrate::crk::cue_from(
        &run.agent_pid,
        run.broker_epoch,
        None,
        "recall",
        &action_digest,
        "low",
        run.working_memory.token_budget,
        8,
    );
    let (crk_json, plan_step) = match crate::substrate::crk::window(state, &cue) {
        Ok((range, manifest, crk_state)) => {
            run.working_memory.context_cids = range.context_cids.clone();
            run.working_memory.staged_candidate_cids = manifest.excluded_conflicts.clone();
            run.working_memory.influence_manifest_id = Some(manifest.manifest_id.clone());
            run.working_memory.moment_range_id = Some(range.moment_range_id.clone());
            run.working_memory.procedure_id = range.procedure_id.clone();
            let procedure = range.procedure_id.as_ref().and_then(|id| {
                crate::substrate::crk::procedure_capsule::load(state.as_ref(), &run.agent_pid, id)
            });
            let next = procedure.as_ref().and_then(|p| {
                crate::substrate::crk::procedure_capsule::next_step_payload(p, 0)
            });
            if next.is_some() {
                run.advance(AgentPhase::Plan);
            }
            (
                json!({
                    "ok": true,
                    "state": crk_state.as_str(),
                    "moment_range_id": range.moment_range_id,
                    "context_cids": range.context_cids,
                    "influence_manifest_id": manifest.manifest_id,
                    "procedure_id": range.procedure_id,
                    "exclusions": manifest.excluded_conflicts,
                    "honesty": "CRK never authorizes — PATE still Allow/Deny",
                }),
                next,
            )
        }
        Err(e) => (
            json!({
                "ok": false,
                "error": "crk_window_failed",
                "message": e,
            }),
            None,
        ),
    };

    if tool_calls.is_empty() {
        checkpoint(state.as_ref(), run)?;
        return Ok(json!({
            "schema": "connector.dal.turn.v1",
            "run_id": run.run_id,
            "phase": run.phase,
            "svf_epoch": svf_epoch(run),
            "project": projection,
            "tool_stubs": tool_stubs,
            "crk": crk_json,
            "plan_step": plan_step,
            "working_memory": run.working_memory,
            "receipts": [],
            "ltl_messages": [],
            "honesty": "No tool_calls — Talk must supply proposals; Ring-1 blocks raw auto-dispatch",
        }));
    }

    run.advance(AgentPhase::Propose);
    let mut proposals = Vec::new();
    for call in tool_calls {
        let p = crate::services::agent_loop::ToolProposal::from_openai_style(
            call,
            "default",
            Some(run.mission_id.clone()),
        )?;
        proposals.push(p);
    }

    run.advance(AgentPhase::Admit);
    let influence_bind = json!({
        "influence_manifest_id": run.working_memory.influence_manifest_id,
        "moment_range_id": run.working_memory.moment_range_id,
        "procedure_id": run.working_memory.procedure_id,
        "context_cids": run.working_memory.context_cids,
        "honesty": "Admit bound to CRK InfluenceManifest — exposure proof, not PATE Allow",
    });
    // Act via agent_loop — sandwich inside tools::dispatch_mcp_tool
    run.advance(AgentPhase::Act);
    let receipts = crate::services::agent_loop::run_tool_proposals_for_run(
        state,
        run,
        proposals,
    )
    .await;

    // LTL session stitch for next Talk
    let mut ltl_messages = Vec::new();
    let assistant = crate::substrate::ltl::assistant_tool_turn(
        assistant_text.unwrap_or(""),
        vec![], // ToolCall structs optional; proposals already executed
        reasoning.map(|s| s.to_string()),
    );
    ltl_messages.push(json!({
        "role": assistant.role,
        "content": assistant.content,
        "reasoning_content": assistant.reasoning_content,
    }));
    for r in &receipts {
        let content = if r.ok {
            serde_json::to_string(&r.result).unwrap_or_else(|_| "{}".into())
        } else {
            r.error.clone().unwrap_or_else(|| "error".into())
        };
        let msg = crate::substrate::ltl::tool_result_turn(&r.call_id, content);
        ltl_messages.push(json!({
            "role": msg.role,
            "content": msg.content,
            "tool_call_id": msg.tool_call_id,
        }));
        let cid = r
            .task_id
            .clone()
            .or_else(|| r.action_digest.clone())
            .unwrap_or_else(|| format!("receipt:{}", r.call_id));
        note_tool_receipt(state, run, &cid, r.ok)?;
    }

    if run.progress.consecutive_no_progress >= 3 {
        run.stop(StopReason::NoProgress);
    }

    checkpoint(state.as_ref(), run)?;
    Ok(json!({
        "schema": "connector.dal.turn.v1",
        "run_id": run.run_id,
        "phase": run.phase,
        "svf_epoch": svf_epoch(run),
        "project": projection,
        "tool_stubs": tool_stubs,
        "crk": crk_json,
        "plan_step": plan_step,
        "influence_bind": influence_bind,
        "working_memory": run.working_memory,
        "receipts": receipts,
        "ltl_messages": ltl_messages,
        "cip": crate::substrate::cip_executive::to_json(
            &crate::substrate::cip_executive::project_from_run(run)
        ),
        "honesty": "DAL owns turn; tools own sandwich; Ring-1 — proposals only, no Talk auto-dispatch",
    }))
}

/// Record a settled tool receipt CID and advance phase.
pub fn note_tool_receipt(
    state: &SharedState,
    run: &mut AgentRunState,
    receipt_cid: &str,
    ok: bool,
) -> Result<(), ConnectorError> {
    run.budgets.tool_calls_used = run.budgets.tool_calls_used.saturating_add(1);
    run.progress.last_verify_ok = ok;
    run.progress.last_receipt_cid = Some(receipt_cid.into());
    if ok {
        run.progress.consecutive_no_progress = 0;
        run.advance(AgentPhase::Verify);
    } else {
        run.progress.consecutive_no_progress =
            run.progress.consecutive_no_progress.saturating_add(1);
        run.advance(AgentPhase::Replan);
    }
    if run.budget_exhausted() {
        run.stop(StopReason::BudgetExhausted);
    }
    checkpoint(state.as_ref(), run)
}

/// Snapshot suitable for mission journal / API (no private reasoning).
pub fn public_snapshot(run: &AgentRunState) -> Value {
    json!({
        "schema": run.schema,
        "run_id": run.run_id,
        "mission_id": run.mission_id,
        "agent_pid": run.agent_pid,
        "phase": run.phase,
        "goal_digest": run.goal_digest,
        "frontier": run.frontier,
        "budgets": run.budgets,
        "stop_reason": run.stop_reason,
        "broker_epoch": run.broker_epoch,
        "iac_epoch": run.iac_epoch,
        "vac_read_set_epoch": run.vac_read_set_epoch,
        "svf_epoch": svf_epoch(run),
        "updated_at_ms": run.updated_at_ms,
        "honesty": "CID-only AgentRunState — no reasoning_content in VAC/AAPI; live broker_epoch stamped",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_id_stable_shape() {
        let r = AgentRunState::new("agent-a", "mission-1", "ship SKU-1");
        assert!(r.run_id.starts_with("dal_"));
        assert_eq!(r.phase, AgentPhase::Observe);
        assert_eq!(r.goal_digest.len(), 64);
    }

    #[test]
    fn cease_stops_a_stamped_loop() {
        assert!(!loop_must_stop(0, 1));
        assert!(!loop_must_stop(2, 2));
        assert!(loop_must_stop(1, 2));
    }

    #[test]
    fn budget_stop() {
        let mut r = AgentRunState::new("a", "m", "g");
        r.budgets.max_steps = 2;
        r.advance(AgentPhase::Act);
        r.advance(AgentPhase::Verify);
        assert!(r.budget_exhausted());
        r.stop(StopReason::BudgetExhausted);
        assert_eq!(r.phase, AgentPhase::Stopped);
    }
}
