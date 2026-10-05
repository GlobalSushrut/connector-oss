//! Agency Governor — Phase B: compose existing PATE/NF³/ActionBinding/BCR.
//! Admit API accepts **only** GovernorInput (typed hat Z). No second admit stack.

use serde_json::{json, Value};

use crate::error::{ConnectorError, DenialReason};
use crate::state::SharedState;
use crate::substrate::pate::{AugmentedTaskUnit, TaskVerdict};

use super::flags::ArcFlags;
use super::governor_input::GovernorInput;
use super::observable::ObservableState;
use super::proposal::EffectProposal;
use super::runtime;
use super::transaction::{AgencyTransaction, TxState};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernorDecision {
    /// Flag off — existing path unchanged.
    NotWired,
    Deny { reason: String },
    WaitingHitl { reason: String },
    /// Gates passed; lease mint is Phase C.
    Reserved {
        tx_id: String,
        action_digest: String,
    },
}

/// Stateless evaluate (tests / no SharedState). Flag off → NotWired.
pub fn evaluate(input: &GovernorInput, proposal: &EffectProposal) -> GovernorDecision {
    let flags = ArcFlags::from_env();
    if !flags.governor {
        return GovernorDecision::NotWired;
    }
    if input.agent_id != proposal.agent_id {
        return GovernorDecision::Deny {
            reason: "agent_id mismatch".into(),
        };
    }
    GovernorDecision::Deny {
        reason: "evaluate_live requires SharedState — use record_pate_admit".into(),
    }
}

/// After successful `pate::admit_*`, drive AgencyTransaction PROPOSED→VALIDATED→RESERVED.
///
/// When `CONNECTOR_ARC_GOVERNOR` is off → Soft no-op Ok.
/// Reuses the ATU already produced by PATE (same gates — not a parallel decision).
/// NF³ + ActionBinding already ran inside `pate::mint_atu`; we compose BCR + STM here.
pub fn record_pate_admit(
    state: &SharedState,
    atu: &AugmentedTaskUnit,
) -> Result<Option<AgencyTransaction>, ConnectorError> {
    let flags = ArcFlags::from_env();
    if !flags.governor {
        tracing::trace!(
            agent_pid = %atu.agent_pid,
            "arc_governor soft skip (CONNECTOR_ARC_GOVERNOR off)"
        );
        return Ok(None);
    }

    let agent_id = &atu.agent_pid;
    let epoch = runtime::epochs().current(agent_id).get();

    let obs = ObservableState {
        schema: ObservableState::SCHEMA.into(),
        proposal_digests: vec![atu.action_digest.clone()],
        effect_history_head: Some(atu.task_id.clone()),
        dim_operator_digest: None,
        ..ObservableState::empty_placeholder()
    };
    let _input = GovernorInput::from_observable(
        agent_id.clone(),
        obs,
        epoch,
        "pate_atu",
        None,
        Some(atu.action_digest.clone()),
    );

    match atu.verdict {
        TaskVerdict::AskHitl | TaskVerdict::Quarantine => {
            let mut tx = AgencyTransaction::new(agent_id, epoch, Some(atu.action_digest.clone()));
            let _ = tx.transition(TxState::WaitingHitl);
            runtime::transactions().insert(tx.clone());
            tracing::info!(
                agent_pid = %agent_id,
                tx_id = %tx.tx_id,
                authority_epoch = epoch,
                "arc_governor: WAITING_HITL (PATE Ask/Quarantine)"
            );
            return Ok(Some(tx));
        }
        TaskVerdict::DeferRedo | TaskVerdict::Block => {
            let mut tx = AgencyTransaction::new(agent_id, epoch, Some(atu.action_digest.clone()));
            let _ = tx.transition(TxState::Denied);
            runtime::transactions().insert(tx.clone());
            return Ok(Some(tx));
        }
        TaskVerdict::Proceed => {}
    }

    // BCR: if tokens budget is configured and exhausted, deny before RESERVED.
    if bcr_tokens_exhausted(state, agent_id) {
        let mut tx = AgencyTransaction::new(agent_id, epoch, Some(atu.action_digest.clone()));
        let _ = tx.transition(TxState::Denied);
        runtime::transactions().insert(tx);
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "arc_governor: BCR token budget exhausted — cannot RESERVE",
        )
        .with_denied_resource("arc.bcr")
        .with_hint("Top up budget then retry — meter, not permanent ban"));
    }

    let mut tx = AgencyTransaction::new(agent_id, epoch, Some(atu.action_digest.clone()));
    tx.idempotency_key = Some(atu.task_id.clone());
    tx.transition(TxState::Validated).map_err(|e| {
        ConnectorError::new(DenialReason::InternalError, e.to_string())
    })?;
    tx.transition(TxState::Reserved).map_err(|e| {
        ConnectorError::new(DenialReason::InternalError, e.to_string())
    })?;
    runtime::transactions().insert(tx.clone());
    tracing::info!(
        agent_pid = %agent_id,
        tx_id = %tx.tx_id,
        digest = %atu.action_digest,
        authority_epoch = epoch,
        "arc_governor: PROPOSED→VALIDATED→RESERVED (PATE admit; NF³ composed in mint_atu)"
    );
    Ok(Some(tx))
}

fn bcr_tokens_exhausted(state: &SharedState, agent_pid: &str) -> bool {
    let Ok(aapi) = state.aapi.lock() else {
        return false;
    };
    let rem = aapi.check_budget(agent_pid, "tokens");
    rem != f64::MAX && rem <= 0.0
}

/// B4 Harden: `CONNECTOR_ARC_HARDEN=1` requires governor engaged (flag on).
/// Soft: governor off is allowed (no-op on admit hooks).
pub fn assert_governor_engaged_when_required() -> Result<(), ConnectorError> {
    let flags = ArcFlags::from_env();
    if flags.harden && !flags.governor {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "arc_harden: CONNECTOR_ARC_HARDEN=1 but CONNECTOR_ARC_GOVERNOR is off — skip governor denied",
        )
        .with_denied_resource("arc.governor")
        .with_hint("Set CONNECTOR_ARC_GOVERNOR=1 or unset CONNECTOR_ARC_HARDEN for Soft/LAB"));
    }
    Ok(())
}

pub fn decision_json(d: &GovernorDecision) -> Value {
    match d {
        GovernorDecision::NotWired => json!({
            "decision": "not_wired",
            "honesty": "ARC governor flag off — existing governed_effect/PATE path unchanged",
        }),
        GovernorDecision::Deny { reason } => json!({ "decision": "deny", "reason": reason }),
        GovernorDecision::WaitingHitl { reason } => {
            json!({ "decision": "waiting_hitl", "reason": reason })
        }
        GovernorDecision::Reserved {
            tx_id,
            action_digest,
        } => json!({
            "decision": "reserved",
            "tx_id": tx_id,
            "action_digest": action_digest,
            "next": "ConsequenceLease mint is Phase C (CONNECTOR_ARC_LEASE)",
        }),
    }
}

/// Unit helper: drive STM with a synthetic Proceed ATU (no SharedState BCR).
#[cfg(test)]
pub fn drive_reserved_for_test(agent_id: &str, action_digest: &str) -> AgencyTransaction {
    let epoch = runtime::epochs().current(agent_id).get();
    let mut tx = AgencyTransaction::new(agent_id, epoch, Some(action_digest.into()));
    tx.transition(TxState::Validated).unwrap();
    tx.transition(TxState::Reserved).unwrap();
    runtime::transactions().insert(tx.clone());
    tx
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::substrate::arc::observable::ObservableState;

    #[test]
    fn evaluate_flag_off_not_wired() {
        std::env::remove_var("CONNECTOR_ARC_GOVERNOR");
        let obs = ObservableState::empty_placeholder();
        let input = GovernorInput::from_observable("a1", obs, 0, "vol", None, None);
        let prop = EffectProposal::new("a1", "tool.x", "t", "op", "sd");
        assert_eq!(evaluate(&input, &prop), GovernorDecision::NotWired);
    }

    #[test]
    fn drive_reserved_stm() {
        let tx = drive_reserved_for_test("arc-b-test", "digest1");
        assert_eq!(tx.state, TxState::Reserved);
        assert!(tx.worldline_edges.iter().any(|e| e.contains("VALIDATED")));
        assert!(tx.worldline_edges.iter().any(|e| e.contains("RESERVED")));
        let proof = tx.proof_export();
        assert_eq!(proof["tx_id"], tx.tx_id);
        assert!(proof.get("authority_epoch").is_some());
        assert_eq!(proof["state"], "RESERVED");
    }

    #[test]
    fn autonomy_ask_is_not_allow() {
        use crate::kernel::action_binding::AutonomyVerdict;
        assert_ne!(AutonomyVerdict::Ask, AutonomyVerdict::Allow);
    }

    #[test]
    fn harden_without_governor_denies() {
        std::env::set_var("CONNECTOR_ARC_HARDEN", "1");
        std::env::remove_var("CONNECTOR_ARC_GOVERNOR");
        let err = assert_governor_engaged_when_required().unwrap_err();
        assert!(
            err.human_readable.contains("arc_harden"),
            "expected arc_harden denial, got {}",
            err.human_readable
        );
        std::env::remove_var("CONNECTOR_ARC_HARDEN");
    }

    #[test]
    fn soft_without_governor_ok() {
        std::env::remove_var("CONNECTOR_ARC_HARDEN");
        std::env::remove_var("CONNECTOR_ARC_GOVERNOR");
        assert!(assert_governor_engaged_when_required().is_ok());
    }
}
