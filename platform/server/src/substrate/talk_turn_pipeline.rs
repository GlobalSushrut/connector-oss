//! talk_turn_pipeline — one snapshot-driven Talk contract for all adapters.
//!
//! Playground, OpenAI-compatible, and stream paths share: snapshot load,
//! generation check, TurnEnvelope mint, static inject, optional GovernedTalkCore
//! prepare, projection finalize, authority evidence.

use std::sync::Arc;

use crate::error::{ConnectorError, DenialReason};
use crate::state::SharedState;
use crate::substrate::agent_runtime_snapshot::{self, AgentRuntimeSnapshot};
use crate::substrate::turn_envelope::{TurnDeadline, TurnEnvelope};

/// Set by Workbench consult so in-process gateway Talk does not re-lock the same agent.
pub const OUTER_SESSION_LEASE_HEADER: &str = "x-connector-outer-session-lease";

pub fn outer_session_lease_held(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(OUTER_SESSION_LEASE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            matches!(
                s.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "held" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

pub const SCHEMA: &str = "connector.talk_turn_pipeline.v1";

#[derive(Debug, Clone)]
pub struct TalkTurnContext {
    pub snapshot: Arc<AgentRuntimeSnapshot>,
    pub envelope: TurnEnvelope,
}

/// Load/compile snapshot, validate generations, mint TurnEnvelope.
pub fn begin_talk_turn(
    state: &SharedState,
    tenant_id: &str,
    principal_id: &str,
    session_id: &str,
    request_body: &str,
    provider_budget_ms: u64,
    prepare_budget_ms: u64,
) -> Result<TalkTurnContext, ConnectorError> {
    let mut snapshot = agent_runtime_snapshot::get_or_compile(state, principal_id, tenant_id);
    let live_identity = state.cells.get_or_create(principal_id).current_epoch();
    let live_broker =
        crate::substrate::llm_context_broker::current_generation(state, principal_id);
    if snapshot
        .assert_generations_match(live_identity, live_broker)
        .is_err()
    {
        // Stale snapshot — recompile once (INV-07 DeferRedo → fresh snap).
        state.runtime_snapshots.invalidate(principal_id);
        snapshot = agent_runtime_snapshot::compile_and_publish(state, principal_id, tenant_id);
        let live_identity = state.cells.get_or_create(principal_id).current_epoch();
        let live_broker =
            crate::substrate::llm_context_broker::current_generation(state, principal_id);
        if let Err(e2) = snapshot.assert_generations_match(live_identity, live_broker) {
            return Err(ConnectorError::new(DenialReason::PolicyDenied, e2)
                .with_hint("Retry Talk after identity/broker mutation settles")
                .with_agent_scope(principal_id));
        }
    }
    let deadline = TurnDeadline::from_now(provider_budget_ms, prepare_budget_ms);
    let envelope = TurnEnvelope::mint_talk(
        tenant_id,
        principal_id,
        session_id,
        snapshot.snapshot_version,
        snapshot.identity_generation,
        snapshot.broker_generation,
        snapshot.quarantine_generation,
        deadline,
        request_body,
    );
    Ok(TalkTurnContext { snapshot, envelope })
}

/// When true, also run GovernedTalkCore prepare (Obey-Once + work unit) off hot path.
pub fn governed_prepare_enabled() -> bool {
    !matches!(
        std::env::var("CONNECTOR_TALK_GOVERNED_PREPARE")
            .ok()
            .as_deref(),
        Some("0") | Some("false") | Some("off")
    )
}

/// Append GovernedTalkCore system blocks when prepare is enabled (sync; call via spawn_blocking).
pub fn append_governed_prepare_blocks(
    state: &SharedState,
    agent_pid: &str,
    model_ref: &str,
    provider: &str,
    messages: &mut Vec<(String, String)>,
) -> Result<(), ConnectorError> {
    if !governed_prepare_enabled() {
        return Ok(());
    }
    let prepared =
        crate::substrate::governed_talk_core::prepare_talk(state, agent_pid, model_ref, provider)?;
    for block in prepared.system_blocks {
        messages.push(("system".into(), block));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_constant() {
        assert!(SCHEMA.contains("talk_turn_pipeline"));
    }

    #[test]
    fn governed_prepare_default_on() {
        std::env::remove_var("CONNECTOR_TALK_GOVERNED_PREPARE");
        assert!(governed_prepare_enabled());
    }

    #[test]
    fn outer_lease_header_detected() {
        let mut h = axum::http::HeaderMap::new();
        assert!(!outer_session_lease_held(&h));
        h.insert(
            OUTER_SESSION_LEASE_HEADER,
            axum::http::HeaderValue::from_static("held"),
        );
        assert!(outer_session_lease_held(&h));
    }
}
