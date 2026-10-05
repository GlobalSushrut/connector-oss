//! Agency scheduler — ScheduleHint only. Never Admits (G4).

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::flags::ArcFlags;

/// Hints for agency-level scheduling. **Cannot** mint leases or flip NF³.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScheduleHint {
    Run,
    Defer,
    Freeze,
    Promote,
    Demote,
    RequestHitl,
    ContractAutonomy,
    Quarantine,
}

impl ScheduleHint {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Run => "RUN",
            Self::Defer => "DEFER",
            Self::Freeze => "FREEZE",
            Self::Promote => "PROMOTE",
            Self::Demote => "DEMOTE",
            Self::RequestHitl => "REQUEST_HITL",
            Self::ContractAutonomy => "CONTRACT_AUTONOMY",
            Self::Quarantine => "QUARANTINE",
        }
    }
}

/// Isolation recommendation — body promote/demote only; AgentID unchanged (G5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IsolationRecommend {
    Stay,
    PromoteMicrovm,
    DemoteProcess,
    FreezeBody,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScheduleDecision {
    pub hint: ScheduleHint,
    pub isolation: IsolationRecommend,
    pub agent_id: String,
    pub same_agent_id: bool,
    pub reason: String,
}

/// Placeholder hint when scheduler flag off / no signal.
pub fn default_hint() -> ScheduleHint {
    ScheduleHint::Run
}

/// Recommend schedule from sensors — **never** calls governor Admit.
pub fn recommend(
    agent_id: &str,
    hitl_waiting: bool,
    high_irreversibility: bool,
    quarantine_requested: bool,
) -> ScheduleDecision {
    let flags = ArcFlags::from_env();
    if !flags.scheduler {
        return ScheduleDecision {
            hint: ScheduleHint::Run,
            isolation: IsolationRecommend::Stay,
            agent_id: agent_id.into(),
            same_agent_id: true,
            reason: "CONNECTOR_ARC_SCHEDULER off — Soft RUN".into(),
        };
    }
    if quarantine_requested {
        return ScheduleDecision {
            hint: ScheduleHint::Quarantine,
            isolation: IsolationRecommend::FreezeBody,
            agent_id: agent_id.into(),
            same_agent_id: true,
            reason: "quarantine requested".into(),
        };
    }
    if hitl_waiting {
        return ScheduleDecision {
            hint: ScheduleHint::RequestHitl,
            isolation: IsolationRecommend::Stay,
            agent_id: agent_id.into(),
            same_agent_id: true,
            reason: "HITL pending".into(),
        };
    }
    if high_irreversibility {
        return ScheduleDecision {
            hint: ScheduleHint::Promote,
            isolation: IsolationRecommend::PromoteMicrovm,
            agent_id: agent_id.into(),
            same_agent_id: true,
            reason: "high irreversibility — promote body, same AgentID".into(),
        };
    }
    ScheduleDecision {
        hint: ScheduleHint::Run,
        isolation: IsolationRecommend::Stay,
        agent_id: agent_id.into(),
        same_agent_id: true,
        reason: "default run".into(),
    }
}

/// Compile-time / API fence: scheduler module has no Admit entrypoint.
/// This function documents the fence; calling it must not authorize consequence.
pub fn assert_cannot_admit() -> Result<(), String> {
    // Intentionally no path to governor::record_pate_admit / lease::mint.
    Ok(())
}

pub fn posture_json() -> Value {
    let flags = ArcFlags::from_env();
    json!({
        "emits": "ScheduleHint",
        "never_admits": true,
        "flag": "CONNECTOR_ARC_SCHEDULER",
        "enforced": flags.scheduler,
        "honesty": "Only arc::governor authorizes consequence — scheduler has no Admit API",
        "hints": [
            "RUN", "DEFER", "FREEZE", "PROMOTE", "DEMOTE",
            "REQUEST_HITL", "CONTRACT_AUTONOMY", "QUARANTINE"
        ],
        "isolation_recommend": ["stay", "promote_microvm", "demote_process", "freeze_body"],
        "g5": "promote/demote body only — AgentID persists",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn promote_keeps_agent_id() {
        std::env::set_var("CONNECTOR_ARC_SCHEDULER", "1");
        let d = recommend("agent-42", false, true, false);
        assert_eq!(d.hint, ScheduleHint::Promote);
        assert_eq!(d.isolation, IsolationRecommend::PromoteMicrovm);
        assert_eq!(d.agent_id, "agent-42");
        assert!(d.same_agent_id);
        std::env::remove_var("CONNECTOR_ARC_SCHEDULER");
    }

    #[test]
    fn cannot_admit_fence() {
        assert!(assert_cannot_admit().is_ok());
    }
}
