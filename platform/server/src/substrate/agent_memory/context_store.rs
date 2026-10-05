//! Context store — deltas, checkpoints, context roots (§19–§20).

use connector_trust::{
    ContextCheckpoint, ContextDelta, ContextReference, ContextTransition, CHECKPOINT_SCHEMA,
    CONTEXT_DELTA_SCHEMA, CONTEXT_TRANSITION_SCHEMA,
};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::state::PlatformState;

pub const DELTA_FOLDER: &str = "agent_memory_deltas";
pub const CHECKPOINT_FOLDER: &str = "agent_memory_checkpoints";
pub const STATE_FOLDER: &str = "agent_memory_context_state";

const REDUCER_VERSION: &str = "connector.reducer.v1";
const POLICY_VERSION: &str = "connector.policy.v1";

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

fn digest_json(v: &serde_json::Value) -> String {
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(v).unwrap_or_default())
    )
}

pub struct AgentContextState {
    pub context_epoch: u64,
    pub context_root: String,
    pub evidence_root: String,
    pub authority_root: String,
    pub delta_seq: u64,
    pub last_checkpoint_ms: i64,
}

pub fn load_state(state: &PlatformState, agent_vid: &str) -> AgentContextState {
    let Ok(es) = state.engine_store.lock() else {
        return default_state(agent_vid);
    };
    if let Ok(Some(v)) = es.folder_get(STATE_FOLDER, agent_vid) {
        return AgentContextState {
            context_epoch: v.get("context_epoch").and_then(|x| x.as_u64()).unwrap_or(1),
            context_root: v
                .get("context_root")
                .and_then(|x| x.as_str())
                .unwrap_or("genesis")
                .into(),
            evidence_root: v
                .get("evidence_root")
                .and_then(|x| x.as_str())
                .unwrap_or("genesis")
                .into(),
            authority_root: v
                .get("authority_root")
                .and_then(|x| x.as_str())
                .unwrap_or("genesis")
                .into(),
            delta_seq: v.get("delta_seq").and_then(|x| x.as_u64()).unwrap_or(0),
            last_checkpoint_ms: v
                .get("last_checkpoint_ms")
                .and_then(|x| x.as_i64())
                .unwrap_or(0),
        };
    }
    default_state(agent_vid)
}

fn default_state(agent_vid: &str) -> AgentContextState {
    AgentContextState {
        context_epoch: 1,
        context_root: format!("{:x}", Sha256::digest(agent_vid.as_bytes())),
        evidence_root: "genesis".into(),
        authority_root: "genesis".into(),
        delta_seq: 0,
        last_checkpoint_ms: 0,
    }
}

fn save_state(state: &PlatformState, agent_vid: &str, st: &AgentContextState) {
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            STATE_FOLDER,
            agent_vid,
            &serde_json::json!({
                "context_epoch": st.context_epoch,
                "context_root": st.context_root,
                "evidence_root": st.evidence_root,
                "authority_root": st.authority_root,
                "delta_seq": st.delta_seq,
                "last_checkpoint_ms": st.last_checkpoint_ms,
            }),
        );
    }
}

pub fn context_ref(state: &PlatformState, agent_vid: &str) -> ContextReference {
    let st = load_state(state, agent_vid);
    ContextReference {
        context_root: st.context_root.clone(),
        epoch: st.context_epoch,
    }
}

pub fn append_delta(
    state: &PlatformState,
    agent_vid: &str,
    path: &str,
    before: Option<&str>,
    after: &str,
    evidence_root: &str,
) -> (ContextDelta, AgentContextState) {
    let mut st = load_state(state, agent_vid);
    st.delta_seq += 1;
    st.evidence_root = evidence_root.into();
    let delta = ContextDelta {
        schema: CONTEXT_DELTA_SCHEMA.into(),
        delta_id: format!("d_{}", Uuid::new_v4().simple()),
        agent_vid: agent_vid.into(),
        seq: st.delta_seq,
        path: path.into(),
        before: before.map(str::to_string),
        after: after.into(),
        context_epoch: st.context_epoch,
        at_ms: now_ms(),
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let key = format!("{agent_vid}:{:08}", st.delta_seq);
        let _ = es.folder_put(
            DELTA_FOLDER,
            &key,
            &serde_json::to_value(&delta).unwrap_or_default(),
        );
    }
    let body = serde_json::json!({
        "prev": st.context_root,
        "delta": delta.delta_id,
        "path": path,
        "after": after,
    });
    st.context_root = digest_json(&body);
    st.context_epoch += 1;
    save_state(state, agent_vid, &st);
    (delta, st)
}

pub fn maybe_checkpoint(
    state: &PlatformState,
    agent_vid: &str,
    reason: &str,
) -> Option<ContextCheckpoint> {
    let mut st = load_state(state, agent_vid);
    let now = now_ms();
    let need = st.delta_seq >= 100
        || (now - st.last_checkpoint_ms) > 300_000
        || reason.contains("authority")
        || reason.contains("policy")
        || reason.contains("consequential");
    if !need {
        return None;
    }
    let prev = latest_checkpoint_id(state, agent_vid);
    let cp = ContextCheckpoint {
        schema: CHECKPOINT_SCHEMA.into(),
        checkpoint_id: format!("CP-{}", Uuid::new_v4().simple()),
        agent_vid: agent_vid.into(),
        execution_id: format!("EX-{}", st.context_epoch),
        epoch: st.context_epoch,
        context_root: st.context_root.clone(),
        evidence_root: st.evidence_root.clone(),
        policy_root: digest_json(&serde_json::json!({ "policy": POLICY_VERSION })),
        authority_root: st.authority_root.clone(),
        previous_checkpoint: prev,
        timestamp_ms: now,
        node_signature: None,
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            CHECKPOINT_FOLDER,
            &cp.checkpoint_id,
            &serde_json::to_value(&cp).unwrap_or_default(),
        );
    }
    st.last_checkpoint_ms = now;
    save_state(state, agent_vid, &st);
    Some(cp)
}

fn latest_checkpoint_id(state: &PlatformState, agent_vid: &str) -> Option<String> {
    let es = state.engine_store.lock().ok()?;
    let keys = es.folder_keys(CHECKPOINT_FOLDER, None).ok()?;
    keys.into_iter()
        .filter(|k| k.contains(agent_vid))
        .last()
}

pub fn record_transition(
    state: &PlatformState,
    agent_vid: &str,
    prev_root: &str,
    next_root: &str,
) -> ContextTransition {
    let tr = ContextTransition {
        schema: CONTEXT_TRANSITION_SCHEMA.into(),
        transition_id: format!("TR-{}", Uuid::new_v4().simple()),
        agent_vid: agent_vid.into(),
        previous_context_root: prev_root.into(),
        evidence_delta_root: next_root.into(),
        owner_delta_root: "none".into(),
        world_delta_root: "none".into(),
        agent_delta_root: next_root.into(),
        reducer_version: REDUCER_VERSION.into(),
        policy_version: POLICY_VERSION.into(),
        next_context_root: next_root.into(),
        timestamp_ms: now_ms(),
        node_signature: None,
    };
    if let Ok(mut es) = state.engine_store.lock() {
        let _ = es.folder_put(
            "agent_memory_transitions",
            &tr.transition_id,
            &serde_json::to_value(&tr).unwrap_or_default(),
        );
    }
    tr
}
