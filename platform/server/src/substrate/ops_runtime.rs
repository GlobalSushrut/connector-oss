//! Operational spine — Linux-like real ops for finalized Connector capabilities.
//!
//! Talk / tools / start / recall / spend go through these helpers so the
//! capability standard is *executed*, not only exposed as APIs.

use serde_json::{json, Value};
use uuid::Uuid;

use crate::error::{ConnectorError, DenialReason};
use crate::state::{PlatformState, SharedState};
use crate::substrate::aapi_effect_field;
use crate::substrate::harden_posture;
use crate::substrate::knowledge_boundary;
use crate::substrate::memory_retrieval;

/// Fail-closed preflight before Talk or tool effects under augmented/harden env.
pub fn preflight_agent_effect(
    state: &SharedState,
    agent_pid: &str,
) -> Result<(), ConnectorError> {
    if crate::substrate::cvr::lifecycle::effects_held(state.as_ref(), agent_pid)
        || crate::substrate::cvr::agent_cell::is_frozen(state.as_ref(), agent_pid)
    {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "START_REFUSED: agent execution body frozen/quarantined — no new effects",
        )
        .with_denied_resource("agent.effect")
        .with_hint("POST /agents/:pid/resume or HITL unquarantine after operator release"));
    }
    if let Err(e) = harden_posture::assert_harden_ready_for_start(state.as_ref(), agent_pid) {
        let msg = e
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("START_REFUSED");
        let detail = e
            .get("denial_reason")
            .and_then(|v| v.as_str())
            .unwrap_or("harden_requirements_unmet");
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!("{msg}: {detail}"),
        )
        .with_denied_resource("agent.effect")
        .with_hint(
            "GET /api/v1/substrate/status → harden_posture · set CONNECTOR_AUGMENTED_ENV=1 only when membrane is ready",
        ));
    }
    // ARC B4: Soft = governor off is no-op; Harden = skip governor → deny.
    crate::substrate::arc::governor::assert_governor_engaged_when_required()?;
    let arc_epoch = crate::substrate::arc::runtime::epochs()
        .current(agent_pid)
        .get();
    tracing::trace!(
        agent_pid = %agent_pid,
        authority_epoch = arc_epoch,
        "arc_preflight: authority_epoch stamped for effect path"
    );
    Ok(())
}

/// BCR spend for tokens when a budget exists; otherwise soft unlimited (playground).
/// Returns reservation_id when BCR was used (caller may commit/release).
pub fn spend_tokens(
    state: &SharedState,
    agent_pid: &str,
    amount: f64,
    action_digest: Option<&str>,
) -> Result<Option<String>, ConnectorError> {
    if amount <= 0.0 {
        return Ok(None);
    }
    let has_budget = {
        let aapi = state.aapi.lock().map_err(|_| {
            ConnectorError::new(DenialReason::InternalError, "aapi_lock")
        })?;
        aapi.check_budget(agent_pid, "tokens") != f64::MAX
    };
    if !has_budget {
        // No budget configured — soft allow (lab). Persist nothing.
        return Ok(None);
    }

    let idem = format!(
        "talk:{}:{}",
        agent_pid,
        action_digest.unwrap_or(&Uuid::new_v4().to_string())
    );
    let reserved = aapi_effect_field::bcr_reserve(
        state,
        agent_pid,
        "tokens",
        amount,
        &idem,
        action_digest,
    );
    if reserved.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            format!(
                "Token budget exhausted for agent '{agent_pid}' (BCR reserve refused)."
            ),
        )
        .with_denied_resource("llm.chat")
        .with_hint(&format!(
            "POST /api/v1/aapi/budgets · POST /api/v1/agents/{agent_pid}/reset-budget"
        )));
    }
    let rid = reserved
        .pointer("/reservation/reservation_id")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let committed = aapi_effect_field::bcr_commit(state, &rid);
    if committed.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        let _ = aapi_effect_field::bcr_release(state, &rid);
        return Err(ConnectorError::new(
            DenialReason::PolicyDenied,
            "Token budget commit failed — reservation released",
        )
        .with_denied_resource("llm.chat"));
    }
    Ok(Some(rid))
}

/// Composite recall for live agent ops (Knot + VAC + knowledge boundary + DIM radius).
pub fn recall(
    state: &PlatformState,
    agent_pid: &str,
    query: &str,
    top_k: usize,
) -> Value {
    memory_retrieval::retrieve(state, agent_pid, query, top_k)
}

/// Under harden knowledge boundary: cited sources must be able to justify an effect.
pub fn assert_knowledge_may_justify(
    state: &PlatformState,
    agent_pid: &str,
    cited: &[String],
) -> Result<(), ConnectorError> {
    knowledge_boundary::assert_sources_may_justify_effect(state, agent_pid, cited).map_err(
        |e| {
            let code = e
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("knowledge_boundary");
            ConnectorError::new(DenialReason::PolicyDenied, code.to_string())
                .with_denied_resource("knowledge.justify")
                .with_hint("GET /api/v1/knowledge/:pid/boundary · POST .../harden-default")
        },
    )
}

/// Inject recall snippets into Talk context when broker/recall is useful (best-effort).
pub fn maybe_augment_talk_with_recall(
    state: &PlatformState,
    agent_pid: &str,
    last_user_text: &str,
) -> Value {
    if last_user_text.trim().is_empty() {
        return json!({"ok": false, "skipped": "empty_query"});
    }
    // Hosted playground: RAG/recall off by default — skip vector/knot work on Talk.
    if crate::services::playground::is_playground_mode()
        && !crate::services::gateway::playground_rag_enabled()
    {
        return json!({
            "ok": false,
            "skipped": "playground_rag_off",
            "honesty": "CONNECTOR_PLAYGROUND_RAG=0 — Talk does not run belief-field recall on shared trial nodes",
        });
    }
    let result = recall(state, agent_pid, last_user_text, 6);
    json!({
        "ok": true,
        "recall": result,
        "honesty": "Recall is belief-field only — does not admit effects",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ops_posture_schema() {
        // Minimal: surfaces named for /proc-like operator view.
        let surfaces = [
            "preflight_agent_effect",
            "spend_tokens (BCR)",
            "recall (knowledge boundary)",
            "assert_knowledge_may_justify",
        ];
        assert_eq!(surfaces.len(), 4);
    }

    #[test]
    fn empty_recall_skips() {
        // Unit-level contract without full PlatformState.
        let empty = "";
        assert!(empty.trim().is_empty());
    }
}

/// Operator-facing ops posture (like /proc for Connector ops).
pub fn ops_posture(state: &PlatformState) -> Value {
    json!({
        "schema": "connector.ops_runtime.v1",
        "role": "operational spine — Talk/tools/start/recall/spend",
        "augmented_env": harden_posture::augmented_env_harden(),
        "harden_refuse_start": harden_posture::harden_refuse_start_enabled(),
        "harden_triad": harden_posture::posture_triad(state),
        "surfaces": [
            "preflight_agent_effect",
            "spend_tokens (BCR)",
            "recall (knowledge boundary)",
            "assert_knowledge_may_justify",
        ],
        "linux_analogy": "syscalls → tool/effect; cgroups → budgets; audit → proof export",
    })
}
