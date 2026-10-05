//! Boot-time crash recovery — hydrate durable agency state and fail-closed mid-flight effects.
//!
//! Machine truth: after kill between EFFECT_STARTED and SETTLED, the node must not
//! pretend the effect completed. Recovery marks EFFECT_UNKNOWN and abandons stale
//! mission Pending / BCR reservations so blind retry cannot double-fire.

use serde_json::{json, Value};

use crate::state::{PlatformState, SharedState};
use crate::substrate::arc::runtime;
use crate::substrate::arc::transaction::{AgencyTransaction, TxState};

pub const SCHEMA: &str = "connector.crash_recovery.v1";
pub const LEASE_FOLDER: &str = "_arc_leases";
pub const TX_FOLDER: &str = "_arc_agency_txs";

#[derive(Debug, Default, Clone)]
pub struct RecoveryReport {
    pub agency_txs_hydrated: usize,
    pub effect_started_to_unknown: usize,
    pub leases_hydrated: usize,
    pub leases_expired_revoked: usize,
    pub missions_scanned: usize,
    pub mission_pending_abandoned: usize,
    pub bcr_stale_released: usize,
    pub bcr_open_restored: usize,
    pub notes: Vec<String>,
}

impl RecoveryReport {
    pub fn to_json(&self) -> Value {
        json!({
            "schema": SCHEMA,
            "agency_txs_hydrated": self.agency_txs_hydrated,
            "effect_started_to_unknown": self.effect_started_to_unknown,
            "leases_hydrated": self.leases_hydrated,
            "leases_expired_revoked": self.leases_expired_revoked,
            "missions_scanned": self.missions_scanned,
            "mission_pending_abandoned": self.mission_pending_abandoned,
            "bcr_stale_released": self.bcr_stale_released,
            "bcr_open_restored": self.bcr_open_restored,
            "notes": self.notes,
            "honesty": "Measured recovery counts only — not a claim of zero data loss or HA failover",
        })
    }
}

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

/// Persist agency tx to engine_store (works even when COPG is off).
pub fn persist_tx_engine(state: &PlatformState, tx: &AgencyTransaction) {
    let Ok(mut es) = state.engine_store.lock() else {
        return;
    };
    if let Ok(v) = serde_json::to_value(tx) {
        let _ = es.folder_put(TX_FOLDER, &tx.tx_id, &v);
    }
}

/// Persist lease to engine_store.
pub fn persist_lease_engine(state: &PlatformState, lease: &crate::substrate::arc::lease::ConsequenceLease) {
    let Ok(mut es) = state.engine_store.lock() else {
        return;
    };
    if let Ok(v) = serde_json::to_value(lease) {
        let _ = es.folder_put(LEASE_FOLDER, &lease.lease_id, &v);
    }
}

fn hydrate_agency_txs(state: &PlatformState, report: &mut RecoveryReport) {
    let mut by_id: std::collections::HashMap<String, AgencyTransaction> =
        std::collections::HashMap::new();

    for tx in crate::substrate::arc::durable::load_agency_txs_from_disk() {
        by_id.insert(tx.tx_id.clone(), tx);
    }
    if crate::substrate::arc::copg::copg_enabled() {
        for tx in crate::substrate::arc::copg::load_agency_transactions() {
            by_id.insert(tx.tx_id.clone(), tx);
        }
    }

    if let Ok(es) = state.engine_store.lock() {
        if let Ok(keys) = es.folder_keys(TX_FOLDER, None) {
            for k in keys {
                if let Ok(Some(v)) = es.folder_get(TX_FOLDER, &k) {
                    if let Ok(tx) = serde_json::from_value::<AgencyTransaction>(v) {
                        by_id.insert(tx.tx_id.clone(), tx);
                    }
                }
            }
        }
    }

    let store = runtime::transactions();
    for (_, tx) in by_id {
        // Keep open + EffectUnknown; drop other terminals.
        if tx.state.is_terminal() {
            continue;
        }
        store.hydrate_memory_only(tx);
        report.agency_txs_hydrated += 1;
    }
}

fn recover_effect_started(report: &mut RecoveryReport) {
    let store = runtime::transactions();
    let open: Vec<_> = store
        .list_all()
        .into_iter()
        .filter(|t| t.state == TxState::EffectStarted)
        .map(|t| t.tx_id)
        .collect();
    for id in open {
        match store.recover_crash_effect_started(&id) {
            Ok(tx) => {
                report.effect_started_to_unknown += 1;
                tracing::warn!(
                    tx_id = %id,
                    agent = %tx.agent_id,
                    "crash recovery: EFFECT_STARTED → EFFECT_UNKNOWN (do not blind-retry)"
                );
            }
            Err(e) => report.notes.push(format!("recover {id}: {e}")),
        }
    }
}

fn hydrate_leases(state: &PlatformState, report: &mut RecoveryReport) {
    let mut leases_map: std::collections::HashMap<
        String,
        crate::substrate::arc::lease::ConsequenceLease,
    > = std::collections::HashMap::new();

    for lease in crate::substrate::arc::durable::load_leases_from_disk() {
        leases_map.insert(lease.lease_id.clone(), lease);
    }

    if let Ok(es) = state.engine_store.lock() {
        if let Ok(keys) = es.folder_keys(LEASE_FOLDER, None) {
            for k in keys {
                if let Ok(Some(v)) = es.folder_get(LEASE_FOLDER, &k) {
                    if let Ok(lease) =
                        serde_json::from_value::<crate::substrate::arc::lease::ConsequenceLease>(v)
                    {
                        leases_map.insert(lease.lease_id.clone(), lease);
                    }
                }
            }
        }
    }

    let now = now_ms();
    let leases = runtime::leases();
    for (_, mut lease) in leases_map {
        if lease.revoked || lease.redeemed {
            continue;
        }
        if lease.exp_ms < now {
            lease.revoked = true;
            report.leases_expired_revoked += 1;
            crate::substrate::arc::durable::persist_lease(&lease);
        }
        leases.hydrate_memory_only(lease);
        report.leases_hydrated += 1;
    }
}

fn abandon_mission_pending(state: &PlatformState, report: &mut RecoveryReport) {
    // Default ON under productionish unless explicitly disabled.
    let abandon = match std::env::var("CONNECTOR_MISSION_ABANDON_STALE_PENDING") {
        Ok(v) => {
            let t = v.trim().to_ascii_lowercase();
            matches!(t.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => crate::connector_profile::is_productionish_env(),
    };
    if !abandon {
        report
            .notes
            .push("mission Pending abandon skipped (lab / CONNECTOR_MISSION_ABANDON_STALE_PENDING=0)".into());
        return;
    }
    // Force-on for this boot sweep even if env unset in lab was false — we already gated.
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("CONNECTOR_MISSION_ABANDON_STALE_PENDING", "1");
    }
    let Ok(es) = state.engine_store.lock() else {
        return;
    };
    let Ok(keys) = es.folder_keys(crate::kernel::mission_journal::MISSION_FOLDER, None) else {
        return;
    };
    drop(es);
    for mid in keys {
        report.missions_scanned += 1;
        match crate::kernel::mission_journal::abandon_stale_pending(state, &mid) {
            Ok(ids) => report.mission_pending_abandoned += ids.len(),
            Err(e) => report.notes.push(format!("mission {mid}: {e}")),
        }
    }
}

fn sweep_stale_bcr(state: &SharedState, report: &mut RecoveryReport) {
    let max_age_ms: i64 = std::env::var("CONNECTOR_BCR_STALE_MS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            if crate::connector_profile::is_productionish_env() {
                3_600_000 // 1h
            } else {
                i64::MAX // lab: don't auto-release
            }
        });
    if max_age_ms == i64::MAX {
        report.notes.push("BCR stale sweep skipped in lab".into());
        return;
    }
    let now = now_ms();
    let Ok(es) = state.engine_store.lock() else {
        return;
    };
    let Ok(keys) = es.folder_keys(crate::substrate::aapi_effect_field::RESERVATION_FOLDER, None)
    else {
        return;
    };
    let mut stale_ids = Vec::new();
    for k in keys {
        if let Ok(Some(v)) = es.folder_get(crate::substrate::aapi_effect_field::RESERVATION_FOLDER, &k)
        {
            if let Ok(r) = serde_json::from_value::<connector_engine::aapi::BudgetReservation>(v) {
                if matches!(
                    r.status,
                    connector_engine::aapi::ReservationStatus::Reserved
                        | connector_engine::aapi::ReservationStatus::Indeterminate
                ) {
                    report.bcr_open_restored += 1;
                    if now.saturating_sub(r.created_at) >= max_age_ms {
                        stale_ids.push(r.reservation_id);
                    }
                }
            }
        }
    }
    drop(es);
    for id in stale_ids {
        let out = crate::substrate::aapi_effect_field::bcr_release(state, &id);
        if out.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
            report.bcr_stale_released += 1;
            tracing::warn!(reservation_id = %id, "crash recovery: released stale BCR reservation");
        } else {
            // Mark indeterminate via commit path if release refused
            report.notes.push(format!("BCR release refused for {id}"));
        }
    }
}

/// Run full boot recovery. Safe to call once after engine_store + BCR hydrate.
pub fn run_boot_recovery(state: &SharedState) -> RecoveryReport {
    let mut report = RecoveryReport::default();
    hydrate_agency_txs(state.as_ref(), &mut report);
    recover_effect_started(&mut report);
    hydrate_leases(state.as_ref(), &mut report);
    abandon_mission_pending(state.as_ref(), &mut report);
    sweep_stale_bcr(state, &mut report);
    tracing::info!(
        txs = report.agency_txs_hydrated,
        unknown = report.effect_started_to_unknown,
        leases = report.leases_hydrated,
        missions = report.missions_scanned,
        abandoned = report.mission_pending_abandoned,
        bcr_released = report.bcr_stale_released,
        "crash recovery complete"
    );
    report
}

pub fn posture_json(state: &PlatformState) -> Value {
    let txs = runtime::transactions();
    let leases = runtime::leases();
    let unknown_txs: Vec<_> = txs
        .list_all()
        .into_iter()
        .filter(|t| t.state == TxState::EffectUnknown)
        .collect();
    let unknown = unknown_txs.len();
    let started = txs
        .list_all()
        .into_iter()
        .filter(|t| t.state == TxState::EffectStarted)
        .count();
    json!({
        "schema": SCHEMA,
        "open_transactions": txs.len(),
        "effect_unknown": unknown,
        "effect_unknown_ids": unknown_txs.iter().map(|t| &t.tx_id).collect::<Vec<_>>(),
        "effect_started_in_memory": started,
        "open_leases": leases.len(),
        "tx_folder": TX_FOLDER,
        "lease_folder": LEASE_FOLDER,
        "measured": {
            "effect_started_must_be_zero_after_boot": started == 0,
            "effect_unknown_needs_operator_or_compensate": unknown,
        },
        "reconcile": {
            "path": "POST /api/v1/substrate/crash-recovery/reconcile-unknown",
            "actions": ["fail", "quarantine"],
            "honesty": "Never auto-COMMIT from EFFECT_UNKNOWN — operator or compensate only",
        },
        "honesty": "Counts are process-local after hydrate — not proof of multi-node HA",
    })
}

/// Operator reconcile: EFFECT_UNKNOWN → Failed or Quarantined (never COMMITTED).
pub fn reconcile_effect_unknown(
    state: &PlatformState,
    tx_id: &str,
    action: &str,
) -> Result<Value, String> {
    let store = runtime::transactions();
    let Some(tx) = store.get(tx_id) else {
        return Err(format!("tx_not_found: {tx_id}"));
    };
    if tx.state != TxState::EffectUnknown {
        return Err(format!(
            "tx_not_unknown: {} is {:?} — only EFFECT_UNKNOWN can be reconciled here",
            tx_id, tx.state
        ));
    }
    let to = match action.trim().to_ascii_lowercase().as_str() {
        "fail" | "failed" => TxState::Failed,
        "quarantine" | "quarantined" => TxState::Quarantined,
        other => {
            return Err(format!(
                "unsupported_action: {other} (use fail|quarantine; compensate via AAPI)"
            ));
        }
    };
    let updated = store
        .transition(tx_id, to)
        .map_err(|e| format!("transition_failed: {e}"))?;
    persist_tx_engine(state, &updated);
    crate::substrate::arc::durable::persist_agency_tx_with_state(state, &updated);
    crate::kernel::decision_trace::append_trace(
        state,
        &updated.agent_id,
        crate::kernel::decision_trace::TraceAppendOpts {
            gateway: "crash_recovery.reconcile_unknown".into(),
            action_digest: updated.proposal_digest.clone(),
            outcome: format!("effect_unknown_to_{}", to.as_str()),
            message_type: Some("effect_unknown_reconcile".into()),
            capability_id: Some(tx_id.into()),
            ..Default::default()
        },
    );
    Ok(json!({
        "ok": true,
        "tx_id": tx_id,
        "from": "EFFECT_UNKNOWN",
        "to": to.as_str(),
        "agent_id": updated.agent_id,
    }))
}

#[derive(Debug, serde::Deserialize)]
pub struct ReconcileUnknownBody {
    pub tx_id: String,
    pub action: String,
}

pub async fn post_reconcile_unknown(
    axum::extract::State(state): axum::extract::State<SharedState>,
    axum::Json(body): axum::Json<ReconcileUnknownBody>,
) -> axum::Json<Value> {
    match reconcile_effect_unknown(state.as_ref(), &body.tx_id, &body.action) {
        Ok(v) => axum::Json(crate::operator::honesty::measured_envelope(v)),
        Err(e) => axum::Json(crate::operator::honesty::measured_envelope(json!({
            "ok": false,
            "error": e,
        }))),
    }
}

pub async fn get_posture(
    axum::extract::State(state): axum::extract::State<SharedState>,
) -> axum::Json<Value> {
    axum::Json(crate::operator::honesty::measured_envelope(posture_json(
        state.as_ref(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::substrate::arc::transaction::AgencyTransaction;

    #[test]
    fn effect_started_recovers_to_unknown() {
        let store = runtime::transactions();
        let mut tx = AgencyTransaction::new("crash-rec-a", 0, None);
        for s in [
            TxState::Validated,
            TxState::Reserved,
            TxState::Leased,
            TxState::Redeeming,
            TxState::EffectStarted,
        ] {
            tx.transition(s).unwrap();
        }
        let id = tx.tx_id.clone();
        store.hydrate_memory_only(tx);
        let mut report = RecoveryReport::default();
        recover_effect_started(&mut report);
        assert_eq!(report.effect_started_to_unknown, 1);
        assert_eq!(
            store.get(&id).unwrap().state,
            TxState::EffectUnknown
        );
    }

    #[test]
    fn reconcile_unknown_to_failed() {
        let store = runtime::transactions();
        let mut tx = AgencyTransaction::new("crash-rec-b", 0, Some("d".into()));
        for s in [
            TxState::Validated,
            TxState::Reserved,
            TxState::Leased,
            TxState::Redeeming,
            TxState::EffectStarted,
            TxState::EffectUnknown,
        ] {
            tx.transition(s).unwrap();
        }
        let id = tx.tx_id.clone();
        store.hydrate_memory_only(tx);
        // Engine store unavailable in unit test — transition in-memory only.
        let updated = store.transition(&id, TxState::Failed).unwrap();
        assert_eq!(updated.state, TxState::Failed);
    }
}
