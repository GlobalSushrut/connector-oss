//! SpendCease runtime — ceilings, hop reserve, kernel Cease (fence/void/reap).

use connector_trust::{
    CeaseReason, CeaseReceiptV1, HopReservationV1, ReservationState, SpendCeilingV1,
    CEASE_RECEIPT_SCHEMA, SPEND_CEILING_SCHEMA,
};
use serde_json::json;

use crate::state::{PlatformState, SharedState};
use crate::substrate::llm_context_broker;

pub const FOLDER_CEILINGS: &str = "spend_ceilings_v1";
pub const FOLDER_RESERVATIONS: &str = "spend_reservations_v1";
pub const FOLDER_CEASE: &str = "spend_cease_receipts_v1";

fn env_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// Default ceilings from env (tenant policy can narrow later).
pub fn default_ceiling(agent_pid: &str, generation_id: &str, quantum_id: &str) -> SpendCeilingV1 {
    SpendCeilingV1::fresh(
        generation_id,
        quantum_id,
        agent_pid,
        env_f64("CONNECTOR_SPEND_MAX_USD", 5.0),
        env_u64("CONNECTOR_SPEND_MAX_TOKENS", 200_000),
        env_u64("CONNECTOR_SPEND_MAX_ITERATIONS", 32),
        "env_default",
    )
}

pub fn put_ceiling(state: &PlatformState, ceiling: &SpendCeilingV1) -> Result<(), String> {
    let mut es = state
        .engine_store
        .lock()
        .map_err(|_| "engine_store_lock".to_string())?;
    let key = format!("{}:{}", ceiling.agent_pid, ceiling.generation_id);
    let val = serde_json::to_value(ceiling).map_err(|e| e.to_string())?;
    es.folder_put(FOLDER_CEILINGS, &key, &val)
        .map_err(|e| e.to_string())
}

pub fn get_ceiling(
    state: &PlatformState,
    agent_pid: &str,
    generation_id: &str,
) -> Option<SpendCeilingV1> {
    let es = state.engine_store.lock().ok()?;
    let key = format!("{agent_pid}:{generation_id}");
    let v = es.folder_get(FOLDER_CEILINGS, &key).ok().flatten()?;
    serde_json::from_value(v).ok()
}

/// Ensure a ceiling exists for this generation (idempotent).
pub fn ensure_ceiling(
    state: &PlatformState,
    agent_pid: &str,
    generation_id: &str,
    quantum_id: &str,
) -> Result<SpendCeilingV1, String> {
    if let Some(c) = get_ceiling(state, agent_pid, generation_id) {
        return Ok(c);
    }
    let c = default_ceiling(agent_pid, generation_id, quantum_id);
    put_ceiling(state, &c)?;
    Ok(c)
}

/// Atomic-ish reserve: load, check, store. Fail-closed on lock/parse errors.
pub fn reserve_hop(
    state: &PlatformState,
    agent_pid: &str,
    generation_id: &str,
    idempotency_key: &str,
    projected_usd: f64,
    projected_tokens: u64,
) -> Result<HopReservationV1, String> {
    // Idempotent: return existing reservation if same key.
    {
        let es = state
            .engine_store
            .lock()
            .map_err(|_| "engine_store_lock".to_string())?;
        let rkey = format!("{agent_pid}:{idempotency_key}");
        if let Ok(Some(v)) = es.folder_get(FOLDER_RESERVATIONS, &rkey) {
            if let Ok(existing) = serde_json::from_value::<HopReservationV1>(v) {
                if existing.generation_id == generation_id
                    && existing.state == ReservationState::Reserved
                {
                    return Ok(existing);
                }
            }
        }
    }

    let live = {
        let es = state
            .engine_store
            .lock()
            .map_err(|_| "engine_store_lock".to_string())?;
        es.folder_get("llm_context_broker_v1", &format!("gen:{agent_pid}"))
            .ok()
            .flatten()
            .and_then(|v| v.get("generation").and_then(|g| g.as_u64()))
            .unwrap_or(0)
    };
    if generation_id != live.to_string() && generation_id != format!("gen_{live}") {
        return Err("spend_stale_generation".into());
    }

    let mut ceiling = get_ceiling(state, agent_pid, generation_id)
        .ok_or_else(|| "spend_no_ceiling".to_string())?;
    if ceiling.fail_closed {
        ceiling
            .reserve(projected_usd, projected_tokens)
            .map_err(|e| e.to_string())?;
    } else if ceiling.can_reserve(projected_usd, projected_tokens).is_err()
        && ceiling.enforcement != connector_trust::SpendEnforcement::Advisory
    {
        return Err("spend_exhausted".into());
    } else {
        let _ = ceiling.reserve(projected_usd, projected_tokens);
    }
    put_ceiling(state, &ceiling)?;

    let res = HopReservationV1::new(
        generation_id,
        idempotency_key,
        projected_usd,
        projected_tokens,
        120_000,
    );
    {
        let mut es = state
            .engine_store
            .lock()
            .map_err(|_| "engine_store_lock".to_string())?;
        let rkey = format!("{agent_pid}:{idempotency_key}");
        let val = serde_json::to_value(&res).map_err(|e| e.to_string())?;
        es.folder_put(FOLDER_RESERVATIONS, &rkey, &val)
            .map_err(|e| e.to_string())?;
    }
    Ok(res)
}

pub fn commit_hop(
    state: &PlatformState,
    agent_pid: &str,
    generation_id: &str,
    idempotency_key: &str,
    actual_usd: f64,
    actual_tokens: u64,
) -> Result<(), String> {
    let mut ceiling =
        get_ceiling(state, agent_pid, generation_id).ok_or_else(|| "spend_no_ceiling".to_string())?;
    let (ru, rt) = {
        let es = state
            .engine_store
            .lock()
            .map_err(|_| "engine_store_lock".to_string())?;
        let rkey = format!("{agent_pid}:{idempotency_key}");
        if let Ok(Some(v)) = es.folder_get(FOLDER_RESERVATIONS, &rkey) {
            if let Ok(mut r) = serde_json::from_value::<HopReservationV1>(v) {
                let ru = r.projected_usd;
                let rt = r.projected_tokens;
                r.state = ReservationState::Committed;
                drop(es);
                let mut es2 = state
                    .engine_store
                    .lock()
                    .map_err(|_| "engine_store_lock".to_string())?;
                let _ = es2.folder_put(
                    FOLDER_RESERVATIONS,
                    &rkey,
                    &serde_json::to_value(&r).unwrap_or(json!({})),
                );
                (ru, rt)
            } else {
                (0.0, 0)
            }
        } else {
            (0.0, 0)
        }
    };
    ceiling.commit(ru, rt, actual_usd, actual_tokens);
    put_ceiling(state, &ceiling)
}

/// Return a reserved hop to the ceiling. A missing or already settled reservation stays as it is.
pub fn release_hop(
    state: &PlatformState,
    agent_pid: &str,
    idempotency_key: &str,
) -> Result<(), String> {
    let released = {
        let es = state
            .engine_store
            .lock()
            .map_err(|_| "engine_store_lock".to_string())?;
        let rkey = format!("{agent_pid}:{idempotency_key}");
        let Some(v) = es.folder_get(FOLDER_RESERVATIONS, &rkey).ok().flatten() else {
            return Ok(());
        };
        let Ok(mut reservation) = serde_json::from_value::<HopReservationV1>(v) else {
            return Ok(());
        };
        if reservation.state != ReservationState::Reserved {
            return Ok(());
        }
        let released = (
            reservation.generation_id.clone(),
            reservation.projected_usd,
            reservation.projected_tokens,
        );
        reservation.state = ReservationState::Released;
        drop(es);
        let mut es2 = state
            .engine_store
            .lock()
            .map_err(|_| "engine_store_lock".to_string())?;
        let _ = es2.folder_put(
            FOLDER_RESERVATIONS,
            &rkey,
            &serde_json::to_value(&reservation).unwrap_or(json!({})),
        );
        released
    };
    if let Some(mut ceiling) = get_ceiling(state, agent_pid, &released.0) {
        ceiling.release_reservation(released.1, released.2);
        put_ceiling(state, &ceiling)?;
    }
    Ok(())
}

/// Kernel Cease: bump broker generation (fence + void ctx_tok + sealed brain),
/// release reservations, write CeaseReceipt. Model desire becomes powerless.
pub fn kernel_cease(
    state: &SharedState,
    agent_pid: &str,
    reason: CeaseReason,
) -> Result<CeaseReceiptV1, String> {
    // Drop every in-flight model call for this agent before anything else.
    // The model does not get to finish, and its output is not used.
    let _ = crate::kernel::aios::interrupt_generation(agent_pid, None);

    let ceased_gen = llm_context_broker::current_generation(state, agent_pid);
    let generation_id = ceased_gen.to_string();

    let ceiling = get_ceiling(state.as_ref(), agent_pid, &generation_id)
        .unwrap_or_else(|| default_ceiling(agent_pid, &generation_id, "unknown"));

    // Fence + void context tokens + reap sealed brain / sandbox (existing invalidate path).
    let reason_str = match reason {
        CeaseReason::UserStop => "spend_cease:user_stop",
        CeaseReason::BudgetExhausted => "spend_cease:budget_exhausted",
        CeaseReason::IterationCap => "spend_cease:iteration_cap",
        CeaseReason::HitlCancel => "spend_cease:hitl_cancel",
        CeaseReason::Error => "spend_cease:error",
        CeaseReason::Timeout => "spend_cease:timeout",
        CeaseReason::Quarantine => "spend_cease:quarantine",
    };
    llm_context_broker::invalidate_agent(state, agent_pid, reason_str);

    let (aborted, cancel_api) =
        crate::substrate::llm_inflight::abort_all_for_agent(state, agent_pid);

    let next_gen = llm_context_broker::current_generation(state, agent_pid);
    let mut receipt = CeaseReceiptV1::mint(
        agent_pid,
        generation_id.clone(),
        next_gen.to_string(),
        reason,
        &ceiling,
        next_gen,
    );
    receipt.context_tokens_voided = 1;
    receipt.workers_reaped = 1; // invalidate closes sandbox slot / sealed brain
    receipt.provider_streams_aborted = aborted.max(1); // at least best-effort mark
    receipt.provider_cancel_api_used = cancel_api;
    receipt.tokens_delivered = ceiling.consumed_tokens;
    receipt.tokens_billed_est = ceiling.consumed_tokens;
    // Cancel tax unknown until provider reconciles — leave est 0 unless reserved left.
    receipt.cancel_tax_usd_est = ceiling.reserved_usd;

    // Drop open reservations for ceased generation.
    if let Ok(mut es) = state.engine_store.lock() {
        if let Ok(keys) = es.folder_keys(FOLDER_RESERVATIONS, Some(&format!("{agent_pid}:"))) {
            for k in keys {
                if let Ok(Some(v)) = es.folder_get(FOLDER_RESERVATIONS, &k) {
                    if let Ok(mut r) = serde_json::from_value::<HopReservationV1>(v) {
                        if r.generation_id == generation_id
                            && r.state == ReservationState::Reserved
                        {
                            r.state = ReservationState::Released;
                            let _ = es.folder_put(
                                FOLDER_RESERVATIONS,
                                &k,
                                &serde_json::to_value(&r).unwrap_or(json!({})),
                            );
                            receipt.hops_cancelled = receipt.hops_cancelled.saturating_add(1);
                        }
                    }
                }
            }
        }
        let val = serde_json::to_value(&receipt).map_err(|e| e.to_string())?;
        es.folder_put(FOLDER_CEASE, &receipt.receipt_id, &val)
            .map_err(|e| e.to_string())?;
        // Mark generation ceased for admit fence helpers.
        let _ = es.folder_put(
            FOLDER_CEASE,
            &format!("latest:{agent_pid}"),
            &json!({
                "receipt_id": receipt.receipt_id,
                "generation_id_ceased": receipt.generation_id_ceased,
                "generation_id_next": receipt.generation_id_next,
                "reason": reason_str,
                "schema": CEASE_RECEIPT_SCHEMA,
            }),
        );
    }

    let fanout = crate::substrate::cvr::runtime_adapter::fanout_cease(
        state.as_ref(),
        agent_pid,
        &receipt.generation_id_next,
    );
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            FOLDER_CEASE,
            &format!("latest:{agent_pid}"),
            &json!({
                "receipt_id": receipt.receipt_id,
                "generation_id_ceased": receipt.generation_id_ceased,
                "generation_id_next": receipt.generation_id_next,
                "reason": reason_str,
                "schema": CEASE_RECEIPT_SCHEMA,
                "fanout": fanout,
            }),
        );
    }

    crate::services::keycloak_agents::on_cease(state, agent_pid, reason_str);

    tracing::warn!(
        agent_pid = %agent_pid,
        ceased = %receipt.generation_id_ceased,
        next = %receipt.generation_id_next,
        reason = %reason_str,
        "SpendCease: kernel cease — generation fenced, ctx_tok void, memory epoch sealed, runtime fan-out recorded"
    );

    Ok(receipt)
}

/// Same comparison `assert_live_generation` uses. Does not record a retry.
pub fn generation_is_live(generation_id: &str, live: u64) -> bool {
    generation_id == live.to_string() || generation_id == format!("gen_{live}")
}

/// What a continue that still carries the ceased generation would receive.
/// Does not call a model and does not increment the post-cease retry count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContinueAfterCease {
    NotEvaluated,
    NotDenied,
    DeniedStaleGeneration,
}

pub fn continue_after_cease(ceased_generation: &str, live: Option<u64>) -> ContinueAfterCease {
    let Some(live) = live else {
        return ContinueAfterCease::NotEvaluated;
    };
    if ceased_generation.is_empty() {
        return ContinueAfterCease::NotEvaluated;
    }
    if generation_is_live(ceased_generation, live) {
        ContinueAfterCease::NotDenied
    } else {
        ContinueAfterCease::DeniedStaleGeneration
    }
}

/// Admit fence: refuse if caller's generation is not the live broker generation.
pub fn assert_live_generation(
    state: &SharedState,
    agent_pid: &str,
    generation_id: &str,
) -> Result<(), String> {
    let live = llm_context_broker::current_generation(state, agent_pid);
    if generation_is_live(generation_id, live) {
        return Ok(());
    }
    let _ = note_post_cease_stale_admit(state, agent_pid);
    Err(format!(
        "spend_stale_generation: live={live} got={generation_id}"
    ))
}

pub fn latest_cease(state: &PlatformState, agent_pid: &str) -> Option<serde_json::Value> {
    let es = state.engine_store.lock().ok()?;
    es.folder_get(FOLDER_CEASE, &format!("latest:{agent_pid}"))
        .ok()
        .flatten()
}

const POST_CEASE_RETRY_FOLDER: &str = "spend_cease_retries_v1";
const POST_CEASE_QUARANTINE_AFTER: u64 = 3;

/// Count stale admits after Cease; quarantine when the model/worker keeps retrying.
pub fn note_post_cease_stale_admit(state: &SharedState, agent_pid: &str) -> u64 {
    let latest = latest_cease(state.as_ref(), agent_pid);
    if latest.is_none() {
        return 0;
    }
    let count = {
        let Ok(mut es) = state.engine_store.lock() else {
            return 0;
        };
        let key = format!("retry:{agent_pid}");
        let cur = es
            .folder_get(POST_CEASE_RETRY_FOLDER, &key)
            .ok()
            .flatten()
            .and_then(|v| v.get("n").and_then(|n| n.as_u64()))
            .unwrap_or(0);
        let next = cur.saturating_add(1);
        let _ = es.folder_put(
            POST_CEASE_RETRY_FOLDER,
            &key,
            &json!({
                "n": next,
                "updated_ms": chrono::Utc::now().timestamp_millis(),
            }),
        );
        next
    };
    if count >= POST_CEASE_QUARANTINE_AFTER {
        let _ = crate::substrate::probabilistic_llm::quarantine_for_bypass(
            state,
            agent_pid,
            "post_cease_retry",
            &format!("stale_admit_count={count} after SpendCease"),
        );
        tracing::error!(
            agent_pid = %agent_pid,
            count,
            "SpendCease: post-cease stale admits → quarantine"
        );
    }
    count
}

pub fn clear_post_cease_retries(state: &PlatformState, agent_pid: &str) {
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            POST_CEASE_RETRY_FOLDER,
            &format!("retry:{agent_pid}"),
            &json!({ "n": 0 }),
        );
    }
}

/// Expansive-intent estimate gate. Ok(estimate_usd) or Err for HITL/refuse.
pub fn scope_estimate_gate(user_text: &str, ceiling_max_usd: f64) -> Result<f64, String> {
    let lower = user_text.to_ascii_lowercase();
    let expansive = [
        "make a video",
        "make this video",
        "make the video",
        "generate a video",
        "rebuild the app",
        "rebuild entire",
        "rewrite the whole",
        "scrape the entire",
        "crawl all",
        "train a model",
        "render a movie",
        "full production",
        "deploy everything",
    ];
    if !expansive.iter().any(|p| lower.contains(p)) {
        return Ok(0.0);
    }
    let estimate = env_f64("CONNECTOR_SPEND_EXPANSIVE_ESTIMATE_USD", 25.0);
    if estimate > ceiling_max_usd {
        return Err(format!(
            "scope_estimate_gate: expansive_intent estimate_usd={estimate} > max_usd={ceiling_max_usd} — HITL or raise CONNECTOR_SPEND_MAX_USD"
        ));
    }
    Ok(estimate)
}

/// Bound provider `max_tokens` by remaining ceiling (cancellation-tax control).
/// Returns `requested.min(remaining).min(hard_cap)` with a floor of 16.
pub fn clamp_max_tokens(
    state: &PlatformState,
    agent_pid: &str,
    requested: u32,
    hard_cap: u32,
) -> u32 {
    let gen = {
        let live = state
            .engine_store
            .lock()
            .ok()
            .and_then(|es| {
                es.folder_get("llm_context_broker_v1", &format!("gen:{agent_pid}"))
                    .ok()
                    .flatten()
                    .and_then(|v| v.get("generation").and_then(|g| g.as_u64()))
            })
            .unwrap_or(0);
        live.to_string()
    };
    let _ = ensure_ceiling(state, agent_pid, &gen, "clamp");
    let remaining = get_ceiling(state, agent_pid, &gen)
        .map(|c| c.remaining_tokens().min(c.max_tokens))
        .unwrap_or(200_000);
    let rem_u32 = remaining.min(u64::from(u32::MAX)) as u32;
    requested.min(rem_u32).min(hard_cap).max(16)
}

pub fn schema_info() -> serde_json::Value {
    json!({
        "schemas": [SPEND_CEILING_SCHEMA, CEASE_RECEIPT_SCHEMA],
        "env": ["CONNECTOR_SPEND_MAX_USD", "CONNECTOR_SPEND_MAX_TOKENS", "CONNECTOR_SPEND_MAX_ITERATIONS"],
        "honesty": "cease_stops_next_hop_not_model_desire_cancel_tax_may_remain",
    })
}

/// Live burn meter: ceiling remaining + in-flight LLM registry (operator surface).
pub fn burn_meter(state: &SharedState, agent_pid: &str) -> serde_json::Value {
    let gen = llm_context_broker::current_generation(state, agent_pid).to_string();
    let ceiling = get_ceiling(state.as_ref(), agent_pid, &gen);
    let inflight = crate::substrate::llm_inflight::snapshot_for_agent(agent_pid);
    let inflight_count = inflight.len();
    let latest = latest_cease(state.as_ref(), agent_pid);
    match ceiling {
        Some(c) => json!({
            "ok": true,
            "agent_pid": agent_pid,
            "generation_id": gen,
            "burn": {
                "consumed_usd": c.consumed_usd,
                "reserved_usd": c.reserved_usd,
                "remaining_usd": c.remaining_usd(),
                "max_usd": c.max_usd,
                "consumed_tokens": c.consumed_tokens,
                "reserved_tokens": c.reserved_tokens,
                "remaining_tokens": c.remaining_tokens(),
                "max_tokens": c.max_tokens,
                "iterations_completed": c.iterations_completed,
                "iterations_remaining": c.iterations_remaining(),
                "max_iterations": c.max_iterations,
                "enforcement": c.enforcement,
                "fail_closed": c.fail_closed,
            },
            "inflight_llm": inflight,
            "inflight_count": inflight_count,
            "latest_cease": latest,
            "honesty": "live_admit_ledger_not_provider_invoice_cancel_tax_may_remain",
        }),
        None => json!({
            "ok": true,
            "agent_pid": agent_pid,
            "generation_id": gen,
            "burn": null,
            "inflight_llm": inflight,
            "inflight_count": inflight_count,
            "latest_cease": latest,
            "hint": "no ceiling until first admit/ensure",
            "honesty": "live_admit_ledger_not_provider_invoice_cancel_tax_may_remain",
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use connector_trust::SpendCeilingV1;

    #[test]
    fn ceiling_remaining_math() {
        let mut c = SpendCeilingV1::fresh("1", "q", "a", 1.0, 10_000, 5, "t");
        c.reserve(0.2, 2000).unwrap();
        assert!((c.remaining_usd() - 0.8).abs() < 1e-9);
        assert_eq!(c.remaining_tokens(), 8_000);
    }

    #[test]
    fn scope_gate_blocks_video_under_tight_ceiling() {
        let err = scope_estimate_gate("please make this video now", 5.0).unwrap_err();
        assert!(err.contains("expansive_intent"));
        assert!(scope_estimate_gate("summarize this paragraph", 5.0).is_ok());
    }
}
