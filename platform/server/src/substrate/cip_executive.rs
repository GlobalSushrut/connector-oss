//! CIP executive — attention, inhibition, goal stack, progress, stop control.
//! Substrate/BG plane only; never imported into kernel admission.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::PlatformState;
use crate::substrate::dynamic_agent_loop::{AgentPhase, AgentRunState, StopReason};

pub const CIP_SCHEMA: &str = "connector.cip.executive.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoalFrame {
    pub goal_digest: String,
    pub priority: u8,
    pub parent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttentionFocus {
    pub primary_cid: Option<String>,
    pub working_set_cids: Vec<String>,
    pub max_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InhibitionGate {
    pub blocked: bool,
    pub reason: String,
    pub until_ms: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CipExecutive {
    pub schema: String,
    pub agent_pid: String,
    pub mission_id: Option<String>,
    pub goals: Vec<GoalFrame>,
    pub attention: AttentionFocus,
    pub inhibition: InhibitionGate,
    pub phase: AgentPhase,
    pub stop: Option<StopReason>,
    pub uncertainty: f32,
}

/// Project CIP executive control from a durable DAL run (or empty default).
pub fn project_from_run(run: &AgentRunState) -> CipExecutive {
    CipExecutive {
        schema: CIP_SCHEMA.into(),
        agent_pid: run.agent_pid.clone(),
        mission_id: Some(run.mission_id.clone()),
        goals: vec![GoalFrame {
            goal_digest: run.goal_digest.clone(),
            priority: 1,
            parent: None,
        }],
        attention: AttentionFocus {
            primary_cid: run.working_memory.context_cids.first().cloned(),
            working_set_cids: run.working_memory.context_cids.clone(),
            max_tokens: run.working_memory.token_budget.max(run.budgets.max_tokens),
        },
        inhibition: InhibitionGate {
            blocked: matches!(run.phase, AgentPhase::HitlWait | AgentPhase::Stopped),
            reason: match run.phase {
                AgentPhase::HitlWait => "hitl_wait".into(),
                AgentPhase::Stopped => "stopped".into(),
                _ => "none".into(),
            },
            until_ms: None,
        },
        phase: run.phase,
        stop: run.stop_reason,
        uncertainty: if run.progress.last_verify_ok {
            0.2
        } else {
            (0.2 + 0.15 * run.progress.consecutive_no_progress as f32).min(0.95)
        },
    }
}

/// Explicit stop — CIP may request; ActionBinding still gates any effect.
pub fn request_stop(run: &mut AgentRunState, reason: StopReason) {
    run.phase = AgentPhase::Stopped;
    run.stop_reason = Some(reason);
}

pub fn should_inhibit_effect(exec: &CipExecutive) -> bool {
    exec.inhibition.blocked || exec.stop.is_some()
}

pub fn load_for_agent(state: &PlatformState, agent_pid: &str) -> Option<CipExecutive> {
    let es = state.engine_store.lock().ok()?;
    let keys = es.folder_keys("dal_run_states", None).ok()?;
    for k in keys {
        if let Ok(Some(v)) = es.folder_get("dal_run_states", &k) {
            if v.get("agent_pid").and_then(|x| x.as_str()) == Some(agent_pid) {
                if let Ok(run) = serde_json::from_value::<AgentRunState>(v) {
                    return Some(project_from_run(&run));
                }
            }
        }
    }
    None
}

pub fn to_json(exec: &CipExecutive) -> Value {
    serde_json::to_value(exec).unwrap_or(json!({ "ok": false }))
}
